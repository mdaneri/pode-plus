#if !NETSTANDARD2_0
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace Pode
{
    public class PodeHttp2Request : PodeRequest
    {
        // HTTP/2 Frame Types
        private const byte FRAME_TYPE_DATA = 0x0;
        private const byte FRAME_TYPE_HEADERS = 0x1;
        private const byte FRAME_TYPE_PRIORITY = 0x2;
        private const byte FRAME_TYPE_RST_STREAM = 0x3;
        private const byte FRAME_TYPE_SETTINGS = 0x4;
        private const byte FRAME_TYPE_PUSH_PROMISE = 0x5;
        private const byte FRAME_TYPE_PING = 0x6;
        private const byte FRAME_TYPE_GOAWAY = 0x7;
        private const byte FRAME_TYPE_WINDOW_UPDATE = 0x8;
        private const byte FRAME_TYPE_CONTINUATION = 0x9;

        // HTTP/2 Frame Flags
        private const byte FLAG_ACK = 0x1;
        private const byte FLAG_END_STREAM = 0x1;
        private const byte FLAG_END_HEADERS = 0x4;
        private const byte FLAG_PADDED = 0x8;
        private const byte FLAG_PRIORITY = 0x20;

        // HTTP/2 Connection Preface
        private static readonly byte[] HTTP2_PREFACE = System.Text.Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // HTTP/2 Properties
        public string HttpMethod { get; private set; }
        public NameValueCollection QueryString { get; private set; }
        public string Protocol { get; private set; } = "HTTP/2.0";
        public string ProtocolVersion { get; private set; } = "2.0";
        public string ContentType { get; private set; }
        public int ContentLength { get; private set; }
        public Encoding ContentEncoding { get; private set; }
        public string UserAgent { get; private set; }
        public string UrlReferrer { get; private set; }
        public Uri Url { get; private set; }
        public Hashtable Headers { get; private set; }
        public byte[] RawBody { get; private set; }
        public string Host { get; private set; }
        public bool AwaitingBody { get; private set; }
        public PodeForm Form { get; private set; }

        // HTTP/2 Specific Properties
        public int StreamId { get; private set; }
        public bool EndOfStream { get; private set; }
        public bool EndOfHeaders { get; private set; }
        public Dictionary<int, Http2Stream> Streams { get; private set; }
        public Dictionary<string, object> Settings { get; private set; }

        private bool _hasReceivedPreface;
        private bool _isHeadersComplete;
        private MemoryStream _bodyStream;
        private SimpleHpackDecoder _hpackDecoder;
        private List<byte> _incompleteFrame;

        private string _body = string.Empty;
        public string Body
        {
            get
            {
                if (RawBody != null && RawBody.Length > 0)
                {
                    _body = ContentEncoding != null ? ContentEncoding.GetString(RawBody) : System.Text.Encoding.UTF8.GetString(RawBody);
                }
                return _body;
            }
        }

        public override bool CloseImmediately
        {
            get => !IsHttpMethodValid();
        }

        public override bool IsProcessable
        {
            get => !CloseImmediately && !AwaitingBody && _isHeadersComplete;
        }

        public PodeHttp2Request(Socket socket, PodeSocket podeSocket, PodeContext context)
            : base(socket, podeSocket, context)
        {
            Type = PodeProtocolType.Http;
            Streams = new Dictionary<int, Http2Stream>();
            Settings = new Dictionary<string, object>();
            _hpackDecoder = new SimpleHpackDecoder();
            _incompleteFrame = new List<byte>();
            ContentEncoding = System.Text.Encoding.UTF8;

            // Initialize default HTTP/2 settings
            InitializeDefaultSettings();
        }

        private void InitializeDefaultSettings()
        {
            Settings["SETTINGS_HEADER_TABLE_SIZE"] = 4096;
            Settings["SETTINGS_ENABLE_PUSH"] = 1;
            Settings["SETTINGS_MAX_CONCURRENT_STREAMS"] = 100;
            Settings["SETTINGS_INITIAL_WINDOW_SIZE"] = 65535;
            Settings["SETTINGS_MAX_FRAME_SIZE"] = 16384;
            Settings["SETTINGS_MAX_HEADER_LIST_SIZE"] = 8192;
        }

        protected override bool ValidateInput(byte[] bytes)
        {
            if (bytes.Length == 0) return false;

            // Check for HTTP/2 connection preface first
            if (!_hasReceivedPreface)
            {
                return bytes.Length >= HTTP2_PREFACE.Length;
            }

            // For HTTP/2, we need at least 9 bytes for a frame header
            return bytes.Length >= 9;
        }

        protected override async Task<bool> Parse(byte[] bytes, CancellationToken cancellationToken)
        {
            if (bytes.Length == 0)
            {
                HttpMethod = string.Empty;
                return true;
            }

            try
            {
                // First check if ALPN negotiated HTTP/1.1 instead of HTTP/2
                if (Context.Data.ContainsKey("AlpnNegotiatedHttp2") && !(bool)Context.Data["AlpnNegotiatedHttp2"])
                {
                    // ALPN negotiated HTTP/1.1, throw exception to trigger fallback in context
                    PodeHelpers.WriteErrorMessage("ALPN negotiated HTTP/1.1, HTTP/2 parser cannot handle this request", Context.Listener, PodeLoggingLevel.Debug, Context);
                    throw new PodeRequestException("HTTP/1.1 protocol negotiated via ALPN, but HTTP/2 parser was selected. This indicates a protocol detection issue.", 422);
                }

                // Check connection preface
                if (!_hasReceivedPreface)
                {
                    if (!CheckConnectionPreface(bytes))
                    {
                        // If this is an HTTPS connection but no proper HTTP/2 preface,
                        // it might be HTTP/1.1 data that wasn't caught by ALPN
                        if (Context.PodeSocket?.IsSsl == true)
                        {
                            PodeHelpers.WriteErrorMessage("HTTPS connection without HTTP/2 preface, this is likely HTTP/1.1 data", Context.Listener, PodeLoggingLevel.Debug, Context);
                            throw new PodeRequestException("HTTP/1.1 request sent to HTTP/2 parser. This indicates a protocol detection issue.", 422);
                        }

                        throw new PodeRequestException("Invalid HTTP/2 connection preface", 400);
                    }
                    _hasReceivedPreface = true;

                    // Remove preface from bytes and continue processing
                    var remainingBytes = new byte[bytes.Length - HTTP2_PREFACE.Length];
                    Array.Copy(bytes, HTTP2_PREFACE.Length, remainingBytes, 0, remainingBytes.Length);
                    bytes = remainingBytes;
                }

                // Add any incomplete frame data from previous parsing
                var allBytes = new List<byte>(_incompleteFrame);
                allBytes.AddRange(bytes);
                _incompleteFrame.Clear();

                var offset = 0;
                while (offset < allBytes.Count)
                {
                    // Need at least 9 bytes for frame header
                    if (allBytes.Count - offset < 9)
                    {
                        // Save incomplete frame for next parse
                        _incompleteFrame.AddRange(allBytes.GetRange(offset, allBytes.Count - offset));
                        break;
                    }

                    var frame = ParseFrame(allBytes.ToArray(), ref offset);
                    if (frame == null)
                    {
                        // Incomplete frame, save for next parse
                        _incompleteFrame.AddRange(allBytes.GetRange(offset - 9, allBytes.Count - (offset - 9)));
                        break;
                    }

                    await ProcessFrame(frame, cancellationToken).ConfigureAwait(false);
                }

                return _isHeadersComplete && !AwaitingBody;
            }
            catch (Exception ex)
            {
                throw new PodeRequestException($"HTTP/2 parsing error: {ex.Message}", 400);
            }
        }

        private bool CheckConnectionPreface(byte[] bytes)
        {
            if (bytes.Length < HTTP2_PREFACE.Length) return false;

            for (int i = 0; i < HTTP2_PREFACE.Length; i++)
            {
                if (bytes[i] != HTTP2_PREFACE[i]) return false;
            }
            return true;
        }

        private Http2Frame ParseFrame(byte[] bytes, ref int offset)
        {
            if (bytes.Length - offset < 9) return null;

            // Parse frame header (9 bytes)
            var length = (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
            var type = bytes[offset + 3];
            var flags = bytes[offset + 4];
            var streamId = ((bytes[offset + 5] & 0x7F) << 24) | (bytes[offset + 6] << 16) |
                          (bytes[offset + 7] << 8) | bytes[offset + 8];

            offset += 9;

            // Check if we have enough bytes for the payload
            if (bytes.Length - offset < length)
            {
                offset -= 9; // Reset offset
                return null;
            }

            // Extract payload
            var payload = new byte[length];
            Array.Copy(bytes, offset, payload, 0, length);
            offset += length;

            return new Http2Frame
            {
                Length = length,
                Type = type,
                Flags = flags,
                StreamId = streamId,
                Payload = payload
            };
        }

        private async Task ProcessFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            switch (frame.Type)
            {
                case FRAME_TYPE_HEADERS:
                    await ProcessHeadersFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_DATA:
                    await ProcessDataFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_SETTINGS:
                    ProcessSettingsFrame(frame);
                    break;
                case FRAME_TYPE_PRIORITY:
                    ProcessPriorityFrame(frame);
                    break;
                case FRAME_TYPE_RST_STREAM:
                    ProcessRstStreamFrame(frame);
                    break;
                case FRAME_TYPE_PING:
                    ProcessPingFrame(frame);
                    break;
                case FRAME_TYPE_GOAWAY:
                    ProcessGoAwayFrame(frame);
                    break;
                case FRAME_TYPE_WINDOW_UPDATE:
                    ProcessWindowUpdateFrame(frame);
                    break;
                case FRAME_TYPE_CONTINUATION:
                    await ProcessContinuationFrame(frame, cancellationToken);
                    break;
            }
        }

        private async Task ProcessHeadersFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            StreamId = frame.StreamId;
            EndOfHeaders = (frame.Flags & FLAG_END_HEADERS) != 0;
            EndOfStream = (frame.Flags & FLAG_END_STREAM) != 0;

            // Get or create stream
            if (!Streams.ContainsKey(StreamId))
            {
                Streams[StreamId] = new Http2Stream { StreamId = StreamId };
            }

            var stream = Streams[StreamId];

            // Decode HPACK headers
            var headers = _hpackDecoder.Decode(frame.Payload);
            foreach (var header in headers)
            {
                stream.Headers[header.Key] = header.Value;
            }

            if (EndOfHeaders)
            {
                await FinalizeHeaders(stream, cancellationToken);
            }
        }

        private async Task ProcessDataFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            if (_bodyStream == null)
            {
                _bodyStream = new MemoryStream();
            }

            await _bodyStream.WriteAsync(frame.Payload, 0, frame.Payload.Length, cancellationToken);

            if ((frame.Flags & FLAG_END_STREAM) != 0)
            {
                RawBody = _bodyStream.ToArray();
                AwaitingBody = false;
            }
        }

        private void ProcessSettingsFrame(Http2Frame frame)
        {
            // Process settings - each setting is 6 bytes (2 bytes ID + 4 bytes value)
            for (int i = 0; i < frame.Payload.Length; i += 6)
            {
                if (i + 5 < frame.Payload.Length)
                {
                    var settingId = (frame.Payload[i] << 8) | frame.Payload[i + 1];
                    var value = (frame.Payload[i + 2] << 24) | (frame.Payload[i + 3] << 16) |
                               (frame.Payload[i + 4] << 8) | frame.Payload[i + 5];

                    var settingName = PodeHttp2Request.GetSettingName(settingId);
                    if (!string.IsNullOrEmpty(settingName))
                    {
                        Settings[settingName] = value;
                    }
                }
            }
        }

        private static string GetSettingName(int settingId)
        {
            switch (settingId)
            {
                case 1:
                    return "SETTINGS_HEADER_TABLE_SIZE";
                case 2:
                    return "SETTINGS_ENABLE_PUSH";
                case 3:
                    return "SETTINGS_MAX_CONCURRENT_STREAMS";
                case 4:
                    return "SETTINGS_INITIAL_WINDOW_SIZE";
                case 5:
                    return "SETTINGS_MAX_FRAME_SIZE";
                case 6:
                    return "SETTINGS_MAX_HEADER_LIST_SIZE";
                default:
                    return null;
            }
        }

        private void ProcessPriorityFrame(Http2Frame frame)
        {
            // Priority frame processing - for now just acknowledge
        }

        private void ProcessRstStreamFrame(Http2Frame frame)
        {
            var errorCode = (frame.Payload[0] << 24) | (frame.Payload[1] << 16) |
                           (frame.Payload[2] << 8) | frame.Payload[3];

            if (Streams.ContainsKey(frame.StreamId))
            {
                Streams[frame.StreamId].Reset = true;
                Streams[frame.StreamId].ErrorCode = errorCode;
            }
        }

        private void ProcessPingFrame(Http2Frame frame)
        {
            // Ping frame - should send PING response with ACK flag
        }

        private void ProcessGoAwayFrame(Http2Frame frame)
        {
            // Connection is being closed
        }

        private void ProcessWindowUpdateFrame(Http2Frame frame)
        {
            // Flow control - update window size
        }

        private async Task ProcessContinuationFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            // Continuation of headers from previous HEADERS frame
            if (Streams.ContainsKey(StreamId))
            {
                var headers = _hpackDecoder.Decode(frame.Payload);
                var stream = Streams[StreamId];

                foreach (var header in headers)
                {
                    stream.Headers[header.Key] = header.Value;
                }

                if ((frame.Flags & FLAG_END_HEADERS) != 0)
                {
                    await FinalizeHeaders(stream, cancellationToken);
                }
            }
        }

        private Task FinalizeHeaders(Http2Stream stream, CancellationToken cancellationToken)
        {
            Headers = new Hashtable(StringComparer.InvariantCultureIgnoreCase);

            foreach (DictionaryEntry header in stream.Headers)
            {
                var key = header.Key.ToString();
                var value = header.Value.ToString();

                // Handle pseudo-headers
                if (key.StartsWith(":"))
                {
                    switch (key)
                    {
                        case ":method":
                            HttpMethod = value.ToUpper();
                            break;
                        case ":path":
                            ParsePath(value);
                            break;
                        case ":authority":
                            Host = value;
                            break;
                        case ":scheme":
                            // Used for URL construction
                            break;
                    }
                }
                else
                {
                    Headers[key] = value;

                    // Set common properties
                    switch (key.ToLower())
                    {
                        case "content-type":
                            ContentType = value;
                            break;
                        case "content-length":
                            int.TryParse(value, out int contentLength);
                            ContentLength = contentLength;
                            break;
                        case "user-agent":
                            UserAgent = value;
                            break;
                        case "referer":
                            UrlReferrer = value;
                            break;
                    }
                }
            }

            // Build URL
            var scheme = IsSsl ? "https" : "http";
            if (!string.IsNullOrEmpty(Host))
            {
                var path = stream.Headers.ContainsKey(":path") ? stream.Headers[":path"].ToString() : "/";
                Url = new Uri($"{scheme}://{Host}{path}");
            }

            _isHeadersComplete = true;
            AwaitingBody = ContentLength > 0 && !EndOfStream;

            return Task.CompletedTask;
        }

        private void ParsePath(string path)
        {
            var qmIndex = path.IndexOf("?");
            if (qmIndex > 0)
            {
                QueryString = System.Web.HttpUtility.ParseQueryString(path.Substring(qmIndex + 1));
            }
        }

        public void ParseFormData()
        {
            Form = PodeForm.Parse(RawBody, ContentType, ContentEncoding);
        }

        public bool IsHttpMethodValid()
        {
            return !string.IsNullOrWhiteSpace(HttpMethod) &&
                   PodeHelpers.HTTP_METHODS.Contains(HttpMethod);
        }

        protected override void Dispose(bool disposing)
        {
            if (IsDisposed) return;

            if (disposing)
            {
                RawBody = null;
                _body = string.Empty;

                _bodyStream?.Dispose();
                _bodyStream = null;

                Form?.Dispose();
                Form = null;

                _hpackDecoder = null;
                Streams?.Clear();
                Settings?.Clear();
            }

            base.Dispose(disposing);
        }
    }

    // Supporting classes
    public class Http2Frame
    {
        public int Length { get; set; }
        public byte Type { get; set; }
        public byte Flags { get; set; }
        public int StreamId { get; set; }
        public byte[] Payload { get; set; }
    }

    public class Http2Stream
    {
        public int StreamId { get; set; }
        public Hashtable Headers { get; set; } = new Hashtable(StringComparer.InvariantCultureIgnoreCase);
        public bool Reset { get; set; }
        public int ErrorCode { get; set; }
        public MemoryStream Data { get; set; }
    }

    // Simplified HPACK decoder - in production, use a full HPACK implementation
    public class SimpleHpackDecoder
    {
        private static readonly Dictionary<int, KeyValuePair<string, string>> StaticTable =
            new Dictionary<int, KeyValuePair<string, string>>
            {
                { 1, new KeyValuePair<string, string>(":authority", "") },
                { 2, new KeyValuePair<string, string>(":method", "GET") },
                { 3, new KeyValuePair<string, string>(":method", "POST") },
                { 4, new KeyValuePair<string, string>(":path", "/") },
                { 5, new KeyValuePair<string, string>(":path", "/index.html") },
                { 6, new KeyValuePair<string, string>(":scheme", "http") },
                { 7, new KeyValuePair<string, string>(":scheme", "https") },
                { 8, new KeyValuePair<string, string>(":status", "200") },
                // Add more static table entries as needed
            };

        public List<KeyValuePair<string, string>> Decode(byte[] headerBlock)
        {
            var headers = new List<KeyValuePair<string, string>>();
            var offset = 0;

            while (offset < headerBlock.Length)
            {
                var header = DecodeHeader(headerBlock, ref offset);
                if (header.HasValue)
                {
                    headers.Add(header.Value);
                }
            }

            return headers;
        }

        private KeyValuePair<string, string>? DecodeHeader(byte[] data, ref int offset)
        {
            if (offset >= data.Length) return null;

            var firstByte = data[offset];

            // Indexed Header Field (starts with 1)
            if ((firstByte & 0x80) != 0)
            {
                var index = DecodeInt(data, ref offset, 7);
                if (StaticTable.ContainsKey(index))
                {
                    return StaticTable[index];
                }
            }
            // Literal Header Field (starts with 01 or 00)
            else
            {
                offset++; // Skip first byte for simplicity

                // For this simplified version, assume literal strings
                var name = DecodeLiteralString(data, ref offset);
                var value = DecodeLiteralString(data, ref offset);

                return new KeyValuePair<string, string>(name, value);
            }

            return null;
        }

        private int DecodeInt(byte[] data, ref int offset, int prefixBits)
        {
            var mask = (1 << prefixBits) - 1;
            var value = data[offset] & mask;
            offset++;

            if (value < mask)
            {
                return value;
            }

            // Variable length integer decoding (simplified)
            var m = 0;
            while (offset < data.Length)
            {
                var b = data[offset++];
                value += (b & 0x7F) << m;
                m += 7;
                if ((b & 0x80) == 0) break;
            }

            return value;
        }

        private string DecodeLiteralString(byte[] data, ref int offset)
        {
            if (offset >= data.Length) return "";

            var length = data[offset++];
            if (offset + length > data.Length) return "";

            var result = Encoding.UTF8.GetString(data, offset, length);
            offset += length;
            return result;
        }
    }
}
#endif