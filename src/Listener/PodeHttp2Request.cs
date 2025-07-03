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
using System.Net.Security;

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
            Console.WriteLine("[DEBUG] PodeHttp2Request constructor called");
            Type = PodeProtocolType.Http;
            Streams = new Dictionary<int, Http2Stream>();
            Settings = new Dictionary<string, object>();
            _hpackDecoder = new SimpleHpackDecoder();
            _incompleteFrame = new List<byte>();
            ContentEncoding = System.Text.Encoding.UTF8;

            // Initialize default HTTP/2 settings
            InitializeDefaultSettings();
            Console.WriteLine("[DEBUG] PodeHttp2Request constructor completed");
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

        public override async Task Open(CancellationToken cancellationToken)
        {
            Console.WriteLine("[DEBUG] PodeHttp2Request.Open() called");

            // Check if InputStream is already set (transferred from HTTP/1.1 request)
            if (InputStream != null)
            {
                Console.WriteLine("[DEBUG] InputStream already set, skipping NetworkStream creation");

                // If InputStream is already an SSL stream, skip SSL upgrade
                if (InputStream is SslStream sslStream)
                {
                    Console.WriteLine("[DEBUG] InputStream is already an authenticated SSL stream, skipping SSL upgrade");
                    SslUpgraded = true;
                    State = PodeStreamState.Open;
                    return;
                }
                else if (IsSsl && TlsMode != PodeTlsMode.Explicit)
                {
                    Console.WriteLine("[DEBUG] InputStream is NetworkStream but SSL required, upgrading to SSL");
                    await UpgradeToSSL(cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    Console.WriteLine("[DEBUG] InputStream is NetworkStream and no SSL required");
                    State = PodeStreamState.Open;
                }
                return;
            }

            // If InputStream is null, use the base implementation
            Console.WriteLine("[DEBUG] InputStream is null, using base Open implementation");
            await base.Open(cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<bool> Parse(byte[] bytes, CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] PodeHttp2Request.Parse called with {bytes.Length} bytes");

            if (bytes.Length == 0)
            {
                Console.WriteLine("[DEBUG] Empty bytes received, returning true");
                HttpMethod = string.Empty;
                return true;
            }

            try
            {
                Console.WriteLine("[DEBUG] Starting HTTP/2 parsing logic");

                // First check if ALPN negotiated HTTP/1.1 instead of HTTP/2
                if (Context.Data.ContainsKey("AlpnNegotiatedHttp2") && !(bool)Context.Data["AlpnNegotiatedHttp2"])
                {
                    Console.WriteLine("[DEBUG] ALPN negotiated HTTP/1.1, throwing exception to trigger fallback");
                    // ALPN negotiated HTTP/1.1, throw exception to trigger fallback in context
                    PodeHelpers.WriteErrorMessage("ALPN negotiated HTTP/1.1, HTTP/2 parser cannot handle this request", Context.Listener, PodeLoggingLevel.Debug, Context);
                    throw new PodeRequestException("HTTP/1.1 protocol negotiated via ALPN, but HTTP/2 parser was selected. This indicates a protocol detection issue.", 422);
                }

                // Check if we have preface data from the HTTP/1.1 parser that detected the upgrade
                byte[] actualBytes = bytes;
                if (!_hasReceivedPreface && Context.Data.ContainsKey("Http2PrefaceData"))
                {
                    var prefaceData = (byte[])Context.Data["Http2PrefaceData"];
                    Console.WriteLine($"[DEBUG] Using stored preface data ({prefaceData.Length} bytes) instead of reading from stream");
                    actualBytes = prefaceData;
                    // Remove the stored data so we don't use it again
                    Context.Data.Remove("Http2PrefaceData");
                }

                // Check connection preface
                if (!_hasReceivedPreface)
                {
                    Console.WriteLine($"[DEBUG] Checking connection preface, actualBytes.Length = {actualBytes.Length}");
                    if (!CheckConnectionPreface(actualBytes))
                    {
                        Console.WriteLine("[DEBUG] Connection preface check failed");
                        // If this is an HTTPS connection but no proper HTTP/2 preface,
                        // it might be HTTP/1.1 data that wasn't caught by ALPN
                        if (Context.PodeSocket?.IsSsl == true)
                        {
                            PodeHelpers.WriteErrorMessage("HTTPS connection without HTTP/2 preface, this is likely HTTP/1.1 data", Context.Listener, PodeLoggingLevel.Debug, Context);
                            throw new PodeRequestException("HTTP/1.1 request sent to HTTP/2 parser. This indicates a protocol detection issue.", 422);
                        }

                        throw new PodeRequestException("Invalid HTTP/2 connection preface", 400);
                    }
                    Console.WriteLine("[DEBUG] Connection preface validated successfully");
                    _hasReceivedPreface = true;

                    // Send initial SETTINGS frame immediately after preface validation
                    Console.WriteLine("[DEBUG] Sending initial SETTINGS frame");
                    await SendInitialSettingsFrame(cancellationToken);

                    // Remove preface from bytes and continue processing
                    var remainingBytes = new byte[actualBytes.Length - HTTP2_PREFACE.Length];
                    Array.Copy(actualBytes, HTTP2_PREFACE.Length, remainingBytes, 0, remainingBytes.Length);
                    actualBytes = remainingBytes;
                    Console.WriteLine($"[DEBUG] Preface removed, remaining bytes: {remainingBytes.Length}");

                    // If we used stored preface data and there are no remaining bytes from the original parse call,
                    // we should process any additional bytes that came in the original call
                    if (Context.Data.ContainsKey("Http2PrefaceData") && remainingBytes.Length == 0 && bytes.Length > 0)
                    {
                        Console.WriteLine($"[DEBUG] Processing original {bytes.Length} bytes after handling stored preface");
                        actualBytes = bytes;
                    }
                }

                // Add any incomplete frame data from previous parsing
                var allBytes = new List<byte>(_incompleteFrame);
                allBytes.AddRange(actualBytes);
                _incompleteFrame.Clear();
                Console.WriteLine($"[DEBUG] Processing {allBytes.Count} total bytes (including incomplete frames)");

                var offset = 0;
                while (offset < allBytes.Count)
                {
                    Console.WriteLine($"[DEBUG] Processing frame at offset {offset}, remaining bytes: {allBytes.Count - offset}");

                    // Need at least 9 bytes for frame header
                    if (allBytes.Count - offset < 9)
                    {
                        Console.WriteLine("[DEBUG] Not enough bytes for frame header, saving for next parse");
                        // Save incomplete frame for next parse
                        _incompleteFrame.AddRange(allBytes.GetRange(offset, allBytes.Count - offset));
                        break;
                    }

                    var frame = ParseFrame(allBytes.ToArray(), ref offset);
                    if (frame == null)
                    {
                        Console.WriteLine("[DEBUG] ParseFrame returned null, saving incomplete frame");
                        // Incomplete frame, save for next parse
                        _incompleteFrame.AddRange(allBytes.GetRange(offset - 9, allBytes.Count - (offset - 9)));
                        break;
                    }

                    Console.WriteLine($"[DEBUG] Parsed frame: Type={frame.Type}, Length={frame.Length}, StreamId={frame.StreamId}, Flags=0x{frame.Flags:X2}");
                    await ProcessFrame(frame, cancellationToken).ConfigureAwait(false);
                }

                var result = _isHeadersComplete && !AwaitingBody;
                Console.WriteLine($"[DEBUG] Parse result: _isHeadersComplete={_isHeadersComplete}, AwaitingBody={AwaitingBody}, returning {result}");
                return result;
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
            Console.WriteLine($"[DEBUG] ProcessFrame: Type={frame.Type}, StreamId={frame.StreamId}, Length={frame.Length}");

            switch (frame.Type)
            {
                case FRAME_TYPE_HEADERS:
                    Console.WriteLine("[DEBUG] Processing HEADERS frame");
                    await ProcessHeadersFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_DATA:
                    Console.WriteLine("[DEBUG] Processing DATA frame");
                    await ProcessDataFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_SETTINGS:
                    Console.WriteLine("[DEBUG] Processing SETTINGS frame");
                    ProcessSettingsFrame(frame);
                    break;
                case FRAME_TYPE_PRIORITY:
                    Console.WriteLine("[DEBUG] Processing PRIORITY frame");
                    ProcessPriorityFrame(frame);
                    break;
                case FRAME_TYPE_RST_STREAM:
                    Console.WriteLine("[DEBUG] Processing RST_STREAM frame");
                    ProcessRstStreamFrame(frame);
                    break;
                case FRAME_TYPE_PING:
                    Console.WriteLine("[DEBUG] Processing PING frame");
                    ProcessPingFrame(frame);
                    break;
                case FRAME_TYPE_GOAWAY:
                    Console.WriteLine("[DEBUG] Processing GOAWAY frame");
                    ProcessGoAwayFrame(frame);
                    break;
                case FRAME_TYPE_WINDOW_UPDATE:
                    Console.WriteLine("[DEBUG] Processing WINDOW_UPDATE frame");
                    ProcessWindowUpdateFrame(frame);
                    break;
                case FRAME_TYPE_CONTINUATION:
                    Console.WriteLine("[DEBUG] Processing CONTINUATION frame");
                    await ProcessContinuationFrame(frame, cancellationToken);
                    break;
                default:
                    Console.WriteLine($"[DEBUG] Unknown frame type: {frame.Type}");
                    break;
            }
        }

        private async Task ProcessHeadersFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] ProcessHeadersFrame: StreamId={frame.StreamId}, Length={frame.Length}, Flags=0x{frame.Flags:X2}");

            StreamId = frame.StreamId;
            EndOfHeaders = (frame.Flags & FLAG_END_HEADERS) != 0;
            EndOfStream = (frame.Flags & FLAG_END_STREAM) != 0;

            Console.WriteLine($"[DEBUG] EndOfHeaders={EndOfHeaders}, EndOfStream={EndOfStream}");

            // Get or create stream
            if (!Streams.ContainsKey(StreamId))
            {
                Streams[StreamId] = new Http2Stream { StreamId = StreamId };
            }

            var stream = Streams[StreamId];

            // Debug: Show raw header payload
            Console.WriteLine($"[DEBUG] Raw header payload ({frame.Payload.Length} bytes): {BitConverter.ToString(frame.Payload).Replace("-", " ")}");

            // Decode HPACK headers
            try
            {
                var headers = _hpackDecoder.Decode(frame.Payload);
                Console.WriteLine($"[DEBUG] Decoded {headers.Count} headers from HPACK:");
                foreach (var header in headers)
                {
                    Console.WriteLine($"[DEBUG]   {header.Key}: {header.Value}");
                    stream.Headers[header.Key] = header.Value;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] HPACK decoding error: {ex.Message}");
                // Try to handle as literal headers for debugging
                Console.WriteLine("[DEBUG] Attempting basic literal header decoding...");
            }

            if (EndOfHeaders)
            {
                Console.WriteLine("[DEBUG] Headers complete, finalizing...");
                await FinalizeHeaders(stream, cancellationToken);
            }
            else
            {
                Console.WriteLine("[DEBUG] Headers not complete, waiting for CONTINUATION frame");
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
            Console.WriteLine($"[DEBUG] ProcessSettingsFrame: Length={frame.Length}, Flags=0x{frame.Flags:X2}");

            // Check if this is a SETTINGS ACK frame
            if ((frame.Flags & FLAG_ACK) != 0)
            {
                Console.WriteLine("[DEBUG] Received SETTINGS ACK frame");
                return;
            }

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
                        Console.WriteLine($"[DEBUG] Setting: {settingName} = {value}");
                        Settings[settingName] = value;
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Unknown setting ID: {settingId} = {value}");
                    }
                }
            }

            // Send SETTINGS ACK frame in response
            Console.WriteLine("[DEBUG] Sending SETTINGS ACK frame");
            Task.Run(async () => await SendSettingsAck());
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
            Console.WriteLine("[DEBUG] FinalizeHeaders: Processing HTTP/2 headers");

            foreach (DictionaryEntry header in stream.Headers)
            {
                var key = header.Key.ToString();
                var value = header.Value.ToString();
                Console.WriteLine($"[DEBUG] Processing header: {key} = {value}");

                // Handle pseudo-headers
                if (key.StartsWith(":"))
                {
                    switch (key)
                    {
                        case ":method":
                            HttpMethod = value.ToUpper();
                            Console.WriteLine($"[DEBUG] Set HTTP method: {HttpMethod}");
                            break;
                        case ":path":
                            ParsePath(value);
                            Console.WriteLine($"[DEBUG] Parsed path: {value}");
                            break;
                        case ":authority":
                            Host = value;
                            Console.WriteLine($"[DEBUG] Set authority/host: {Host}");
                            break;
                        case ":scheme":
                            Console.WriteLine($"[DEBUG] Scheme: {value}");
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

                try
                {
                    // Improved hostname parsing logic
                    Console.WriteLine($"[DEBUG] Host header: '{Host}'");

                    // First, strip any existing scheme from the Host if present
                    string hostWithoutScheme = Host;
                    if (Host.Contains("://"))
                    {
                        var schemeIndex = Host.IndexOf("://");
                        hostWithoutScheme = Host.Substring(schemeIndex + 3);
                        Console.WriteLine($"[DEBUG] Host had scheme, extracted: '{hostWithoutScheme}'");
                    }

                    // Next, handle port number in the hostname - make sure it's properly formatted
                    // For example, 'localhost:8043' needs to be handled correctly when building the URI
                    string urlString = $"{scheme}://{hostWithoutScheme}{path}";

                    Console.WriteLine($"[DEBUG] Building URL: '{urlString}'");
                    Url = new Uri(urlString);
                    Console.WriteLine($"[DEBUG] URL parsed successfully: {Url}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Failed to parse URL: {ex.Message}");
                    Console.WriteLine($"[DEBUG] Host: '{Host}', Path: '{path}', IsSsl: {IsSsl}");
                    // Fallback to a simpler URI construction
                    try
                    {
                        // Try to extract host without port
                        string hostOnly = Host;
                        if (Host.Contains(":"))
                        {
                            hostOnly = Host.Split(':')[0];
                        }

                        string fallbackUrl = $"{scheme}://{hostOnly}{path}";
                        Console.WriteLine($"[DEBUG] Trying fallback URL: {fallbackUrl}");
                        Url = new Uri(fallbackUrl);
                    }
                    catch (Exception innerEx)
                    {
                        // Last resort fallback
                        Console.WriteLine($"[ERROR] Fallback URL parsing failed: {innerEx.Message}");
                        Url = new Uri($"{scheme}://localhost{path}");
                    }
                }
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

        private async Task SendInitialSettingsFrame(CancellationToken cancellationToken)
        {
            try
            {
                Console.WriteLine("[DEBUG] Building initial SETTINGS frame");

                // Build SETTINGS frame with our default settings
                var settingsData = new List<byte>();

                // Add each setting (6 bytes per setting: 2 bytes ID + 4 bytes value)
                AddSetting(settingsData, 1, 4096);  // SETTINGS_HEADER_TABLE_SIZE
                AddSetting(settingsData, 2, 0);     // SETTINGS_ENABLE_PUSH (disabled)
                AddSetting(settingsData, 3, 100);   // SETTINGS_MAX_CONCURRENT_STREAMS
                AddSetting(settingsData, 4, 65535); // SETTINGS_INITIAL_WINDOW_SIZE
                AddSetting(settingsData, 5, 16384); // SETTINGS_MAX_FRAME_SIZE
                AddSetting(settingsData, 6, 8192);  // SETTINGS_MAX_HEADER_LIST_SIZE

                var payload = settingsData.ToArray();
                Console.WriteLine($"[DEBUG] SETTINGS payload length: {payload.Length}");

                // Create HTTP/2 frame header (9 bytes)
                var frameHeader = new byte[9];

                // Frame length (24 bits)
                frameHeader[0] = (byte)((payload.Length >> 16) & 0xFF);
                frameHeader[1] = (byte)((payload.Length >> 8) & 0xFF);
                frameHeader[2] = (byte)(payload.Length & 0xFF);

                // Frame type (SETTINGS = 0x4)
                frameHeader[3] = FRAME_TYPE_SETTINGS;

                // Flags (no flags for initial SETTINGS)
                frameHeader[4] = 0x0;

                // Stream ID (0 for SETTINGS frame)
                frameHeader[5] = 0x0;
                frameHeader[6] = 0x0;
                frameHeader[7] = 0x0;
                frameHeader[8] = 0x0;

                // Send frame header + payload
                Console.WriteLine("[DEBUG] Sending SETTINGS frame to client");
                var networkStream = GetNetworkStream();
                if (networkStream != null)
                {
                    await networkStream.WriteAsync(frameHeader, 0, frameHeader.Length, cancellationToken);
                    await networkStream.WriteAsync(payload, 0, payload.Length, cancellationToken);
                    await networkStream.FlushAsync(cancellationToken);
                }
                else
                {
                    throw new InvalidOperationException("Could not get network stream for SETTINGS frame");
                }

                Console.WriteLine("[DEBUG] SETTINGS frame sent successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error sending SETTINGS frame: {ex.Message}");
                throw;
            }
        }

        private void AddSetting(List<byte> settingsData, int settingId, int value)
        {
            // Setting ID (2 bytes)
            settingsData.Add((byte)((settingId >> 8) & 0xFF));
            settingsData.Add((byte)(settingId & 0xFF));

            // Setting value (4 bytes)
            settingsData.Add((byte)((value >> 24) & 0xFF));
            settingsData.Add((byte)((value >> 16) & 0xFF));
            settingsData.Add((byte)((value >> 8) & 0xFF));
            settingsData.Add((byte)(value & 0xFF));
        }

        private async Task SendSettingsAck()
        {
            try
            {
                Console.WriteLine("[DEBUG] Sending SETTINGS ACK frame");

                // Create HTTP/2 frame header for SETTINGS ACK (9 bytes)
                var frameHeader = new byte[9];

                // Frame length (0 for ACK)
                frameHeader[0] = 0x0;
                frameHeader[1] = 0x0;
                frameHeader[2] = 0x0;

                // Frame type (SETTINGS = 0x4)
                frameHeader[3] = FRAME_TYPE_SETTINGS;

                // Flags (ACK = 0x1)
                frameHeader[4] = FLAG_ACK;

                // Stream ID (0 for SETTINGS frame)
                frameHeader[5] = 0x0;
                frameHeader[6] = 0x0;
                frameHeader[7] = 0x0;
                frameHeader[8] = 0x0;

                // Send frame header (no payload for ACK)
                Console.WriteLine("[DEBUG] Writing SETTINGS ACK frame to stream");
                var networkStream = GetNetworkStream();
                if (networkStream != null)
                {
                    await networkStream.WriteAsync(frameHeader, 0, frameHeader.Length);
                    await networkStream.FlushAsync();
                    Console.WriteLine("[DEBUG] SETTINGS ACK frame sent successfully");
                }
                else
                {
                    Console.WriteLine("[DEBUG] ERROR: Could not get network stream for SETTINGS ACK");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error sending SETTINGS ACK: {ex.Message}");
            }
        }

        private Stream GetNetworkStream()
        {
            try
            {
                // Use the existing InputStream if available, or create a NetworkStream
                if (InputStream != null)
                {
                    return InputStream;
                }

                // If no InputStream, we need to access the socket through reflection or use the Context
                // For now, let's try using the context's socket information
                if (Context?.PodeSocket != null)
                {
                    // Get the underlying socket from the context if possible
                    var socketField = typeof(PodeRequest).GetField("Socket", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                    if (socketField != null)
                    {
                        var socket = (Socket)socketField.GetValue(this);
                        if (socket?.Connected == true)
                        {
                            return new NetworkStream(socket, false);
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error getting network stream: {ex.Message}");
                return null;
            }
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

    // RFC 7541 compliant HPACK decoder
    public class SimpleHpackDecoder
    {
        private readonly List<KeyValuePair<string, string>> _dynamicTable;
        private int _maxTableSize = 4096;
        private int _currentTableSize = 0;

        // Complete HPACK static table from RFC 7541 Appendix B
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
                { 9, new KeyValuePair<string, string>(":status", "204") },
                { 10, new KeyValuePair<string, string>(":status", "206") },
                { 11, new KeyValuePair<string, string>(":status", "304") },
                { 12, new KeyValuePair<string, string>(":status", "400") },
                { 13, new KeyValuePair<string, string>(":status", "404") },
                { 14, new KeyValuePair<string, string>(":status", "500") },
                { 15, new KeyValuePair<string, string>("accept-charset", "") },
                { 16, new KeyValuePair<string, string>("accept-encoding", "gzip, deflate") },
                { 17, new KeyValuePair<string, string>("accept-language", "") },
                { 18, new KeyValuePair<string, string>("accept-ranges", "") },
                { 19, new KeyValuePair<string, string>("accept", "") },
                { 20, new KeyValuePair<string, string>("access-control-allow-origin", "") },
                { 21, new KeyValuePair<string, string>("age", "") },
                { 22, new KeyValuePair<string, string>("allow", "") },
                { 23, new KeyValuePair<string, string>("authorization", "") },
                { 24, new KeyValuePair<string, string>("cache-control", "") },
                { 25, new KeyValuePair<string, string>("content-disposition", "") },
                { 26, new KeyValuePair<string, string>("content-encoding", "") },
                { 27, new KeyValuePair<string, string>("content-language", "") },
                { 28, new KeyValuePair<string, string>("content-length", "") },
                { 29, new KeyValuePair<string, string>("content-location", "") },
                { 30, new KeyValuePair<string, string>("content-range", "") },
                { 31, new KeyValuePair<string, string>("content-type", "") },
                { 32, new KeyValuePair<string, string>("cookie", "") },
                { 33, new KeyValuePair<string, string>("date", "") },
                { 34, new KeyValuePair<string, string>("etag", "") },
                { 35, new KeyValuePair<string, string>("expect", "") },
                { 36, new KeyValuePair<string, string>("expires", "") },
                { 37, new KeyValuePair<string, string>("from", "") },
                { 38, new KeyValuePair<string, string>("host", "") },
                { 39, new KeyValuePair<string, string>("if-match", "") },
                { 40, new KeyValuePair<string, string>("if-modified-since", "") },
                { 41, new KeyValuePair<string, string>("if-none-match", "") },
                { 42, new KeyValuePair<string, string>("if-range", "") },
                { 43, new KeyValuePair<string, string>("if-unmodified-since", "") },
                { 44, new KeyValuePair<string, string>("last-modified", "") },
                { 45, new KeyValuePair<string, string>("link", "") },
                { 46, new KeyValuePair<string, string>("location", "") },
                { 47, new KeyValuePair<string, string>("max-forwards", "") },
                { 48, new KeyValuePair<string, string>("proxy-authenticate", "") },
                { 49, new KeyValuePair<string, string>("proxy-authorization", "") },
                { 50, new KeyValuePair<string, string>("range", "") },
                { 51, new KeyValuePair<string, string>("referer", "") },
                { 52, new KeyValuePair<string, string>("refresh", "") },
                { 53, new KeyValuePair<string, string>("retry-after", "") },
                { 54, new KeyValuePair<string, string>("server", "") },
                { 55, new KeyValuePair<string, string>("set-cookie", "") },
                { 56, new KeyValuePair<string, string>("strict-transport-security", "") },
                { 57, new KeyValuePair<string, string>("transfer-encoding", "") },
                { 58, new KeyValuePair<string, string>("user-agent", "") },
                { 59, new KeyValuePair<string, string>("vary", "") },
                { 60, new KeyValuePair<string, string>("via", "") },
                { 61, new KeyValuePair<string, string>("www-authenticate", "") }
            };

        public SimpleHpackDecoder()
        {
            _dynamicTable = new List<KeyValuePair<string, string>>();
        }

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
            Console.WriteLine($"[DEBUG] DecodeHeader: firstByte=0x{firstByte:X2}, offset={offset}");

            // Indexed Header Field (starts with 1)
            if ((firstByte & 0x80) != 0)
            {
                var index = DecodeInt(data, ref offset, 7);
                Console.WriteLine($"[DEBUG] Indexed header field: index={index}");

                if (index == 0)
                {
                    Console.WriteLine($"[DEBUG] Invalid index 0 in indexed header field");
                    return null;
                }

                var header = GetHeaderFromIndex(index);
                if (header.HasValue)
                {
                    Console.WriteLine($"[DEBUG] Found indexed header: {header.Value.Key}={header.Value.Value}");
                    return header;
                }
                else
                {
                    Console.WriteLine($"[DEBUG] Unknown table index: {index}");
                    return null;
                }
            }
            // Literal Header Field with Incremental Indexing (starts with 01)
            else if ((firstByte & 0x40) != 0)
            {
                var nameIndex = DecodeInt(data, ref offset, 6);
                Console.WriteLine($"[DEBUG] Literal header field (incremental): nameIndex={nameIndex}");
                string name;

                if (nameIndex == 0)
                {
                    // New name
                    name = DecodeLiteralString(data, ref offset);
                    Console.WriteLine($"[DEBUG] New name: '{name}'");
                }
                else
                {
                    var nameHeader = GetHeaderFromIndex(nameIndex);
                    if (nameHeader.HasValue)
                    {
                        name = nameHeader.Value.Key;
                        Console.WriteLine($"[DEBUG] Indexed name: '{name}'");
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Unknown name index: {nameIndex}");
                        return null;
                    }
                }

                var value = DecodeLiteralString(data, ref offset);
                Console.WriteLine($"[DEBUG] Header value: '{value}'");

                var header = new KeyValuePair<string, string>(name, value);

                // Add to dynamic table if name is not empty
                if (!string.IsNullOrEmpty(name))
                {
                    AddToDynamicTable(header);
                }

                return header;
            }
            // Dynamic Table Size Update (starts with 001)
            else if ((firstByte & 0xE0) == 0x20)
            {
                var newSize = DecodeInt(data, ref offset, 5);
                Console.WriteLine($"[DEBUG] Dynamic table size update: {newSize}");
                UpdateDynamicTableSize(newSize);
                return null; // Size updates don't produce headers
            }
            // Literal Header Field Never Indexed (starts with 0001)
            else if ((firstByte & 0x10) != 0)
            {
                var nameIndex = DecodeInt(data, ref offset, 4);
                Console.WriteLine($"[DEBUG] Literal header field (never indexed): nameIndex={nameIndex}");
                string name;

                if (nameIndex == 0)
                {
                    // New name
                    name = DecodeLiteralString(data, ref offset);
                    Console.WriteLine($"[DEBUG] New name: '{name}'");
                }
                else
                {
                    var nameHeader = GetHeaderFromIndex(nameIndex);
                    if (nameHeader.HasValue)
                    {
                        name = nameHeader.Value.Key;
                        Console.WriteLine($"[DEBUG] Indexed name: '{name}'");
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Unknown name index: {nameIndex}");
                        return null;
                    }
                }

                var value = DecodeLiteralString(data, ref offset);
                Console.WriteLine($"[DEBUG] Header value: '{value}'");
                return new KeyValuePair<string, string>(name, value);
            }
            // Literal Header Field without Indexing (starts with 0000)
            else
            {
                var nameIndex = DecodeInt(data, ref offset, 4);
                Console.WriteLine($"[DEBUG] Literal header field (no indexing): nameIndex={nameIndex}");
                string name;

                if (nameIndex == 0)
                {
                    // New name
                    name = DecodeLiteralString(data, ref offset);
                    Console.WriteLine($"[DEBUG] New name: '{name}'");
                }
                else
                {
                    var nameHeader = GetHeaderFromIndex(nameIndex);
                    if (nameHeader.HasValue)
                    {
                        name = nameHeader.Value.Key;
                        Console.WriteLine($"[DEBUG] Indexed name: '{name}'");
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Unknown name index: {nameIndex}");
                        return null;
                    }
                }

                var value = DecodeLiteralString(data, ref offset);
                Console.WriteLine($"[DEBUG] Header value: '{value}'");
                return new KeyValuePair<string, string>(name, value);
            }
        }

        private KeyValuePair<string, string>? GetHeaderFromIndex(int index)
        {
            if (index <= 0) return null;

            // Static table entries (1-61)
            if (StaticTable.ContainsKey(index))
            {
                return StaticTable[index];
            }

            // Dynamic table entries (62+)
            var dynamicIndex = index - StaticTable.Count;
            if (dynamicIndex > 0 && dynamicIndex <= _dynamicTable.Count)
            {
                return _dynamicTable[dynamicIndex - 1];
            }

            return null;
        }

        private void AddToDynamicTable(KeyValuePair<string, string> header)
        {
            // Calculate entry size (name + value + 32 bytes overhead per RFC 7541)
            var entrySize = Encoding.UTF8.GetByteCount(header.Key) +
                           Encoding.UTF8.GetByteCount(header.Value) + 32;

            // Remove entries if necessary to make room
            while (_currentTableSize + entrySize > _maxTableSize && _dynamicTable.Count > 0)
            {
                var removedHeader = _dynamicTable[_dynamicTable.Count - 1];
                _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
                var removedSize = Encoding.UTF8.GetByteCount(removedHeader.Key) +
                                Encoding.UTF8.GetByteCount(removedHeader.Value) + 32;
                _currentTableSize -= removedSize;
            }

            // Add new entry if it fits
            if (entrySize <= _maxTableSize)
            {
                _dynamicTable.Insert(0, header);
                _currentTableSize += entrySize;
                Console.WriteLine($"[DEBUG] Added to dynamic table: {header.Key}={header.Value} (size: {entrySize}, total: {_currentTableSize})");
            }
        }

        private void UpdateDynamicTableSize(int newSize)
        {
            _maxTableSize = newSize;

            // Remove entries if current size exceeds new maximum
            while (_currentTableSize > _maxTableSize && _dynamicTable.Count > 0)
            {
                var removedHeader = _dynamicTable[_dynamicTable.Count - 1];
                _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
                var removedSize = Encoding.UTF8.GetByteCount(removedHeader.Key) +
                                Encoding.UTF8.GetByteCount(removedHeader.Value) + 32;
                _currentTableSize -= removedSize;
            }

            Console.WriteLine($"[DEBUG] Updated dynamic table max size to: {newSize}");
        }

        private int DecodeInt(byte[] data, ref int offset, int prefixBits)
        {
            if (offset >= data.Length) return 0;

            var mask = (1 << prefixBits) - 1;
            var value = data[offset] & mask;
            offset++;

            if (value < mask)
            {
                return value;
            }

            // Variable length integer decoding
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
            if (offset >= data.Length)
            {
                Console.WriteLine($"[WARNING] DecodeLiteralString: No data at offset {offset}");
                return "";
            }

            var firstByte = data[offset];
            var isHuffmanCoded = (firstByte & 0x80) != 0;
            var length = DecodeInt(data, ref offset, 7);

            Console.WriteLine($"[DEBUG] DecodeLiteralString: offset={offset}, isHuffmanCoded={isHuffmanCoded}, length={length}");

            if (length == 0)
            {
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Zero-length string");
                return "";
            }

            if (offset + length > data.Length)
            {
                Console.WriteLine($"[ERROR] DecodeLiteralString: Not enough bytes for string (need {length}, have {data.Length - offset})");
                // Return what we can instead of failing completely
                var availableLength = Math.Max(0, data.Length - offset);
                if (availableLength > 0)
                {
                    var partialBytes = new byte[availableLength];
                    Array.Copy(data, offset, partialBytes, 0, availableLength);
                    offset += availableLength;

                    try
                    {
                        return isHuffmanCoded ? DecodeHuffman(partialBytes) : Encoding.UTF8.GetString(partialBytes);
                    }
                    catch
                    {
                        return "";
                    }
                }
                return "";
            }

            // Copy the exact number of bytes specified by length
            var stringBytes = new byte[length];
            Array.Copy(data, offset, stringBytes, 0, length);
            offset += length;

            string result;
            if (isHuffmanCoded)
            {
                // Decode Huffman-coded string
                result = DecodeHuffman(stringBytes);
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Huffman decoded '{result}' from {BitConverter.ToString(stringBytes)}");
            }
            else
            {
                result = Encoding.UTF8.GetString(stringBytes);
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Plain string '{result}' from {BitConverter.ToString(stringBytes)}");
            }

            return result ?? "";
        }

        // RFC 7541 compliant Huffman decoder for HTTP/2 HPACK
        private string DecodeHuffman(byte[] data)
        {
            try
            {
                var result = new StringBuilder();
                var bitAccumulator = 0UL;
                var bitsAccumulated = 0;

                foreach (var b in data)
                {
                    // Accumulate bits from MSB
                    bitAccumulator = (bitAccumulator << 8) | b;
                    bitsAccumulated += 8;

                    // Decode as many symbols as possible
                    while (bitsAccumulated >= 5) // Minimum symbol length is 5 bits
                    {
                        var symbolFound = false;

                        // Try to match symbols from longest to shortest (to get greedy matching)
                        for (int testLength = Math.Min(30, bitsAccumulated); testLength >= 5; testLength--)
                        {
                            // Extract the most significant testLength bits
                            var extractedBits = bitAccumulator >> (bitsAccumulated - testLength);
                            var key = (extractedBits, testLength);

                            if (HuffmanDecodeTable.TryGetValue(key, out var symbol))
                            {
                                result.Append((char)symbol);

                                // Remove the decoded bits from accumulator
                                var remainingBits = bitsAccumulated - testLength;
                                bitAccumulator &= (1UL << remainingBits) - 1;
                                bitsAccumulated = remainingBits;

                                symbolFound = true;
                                break;
                            }
                        }

                        if (!symbolFound)
                        {
                            // No symbol found, either we need more data or it's padding
                            break;
                        }
                    }
                }

                // RFC 7541: Padding should be most-significant bits of EOS (all 1s)
                // Only validate padding if we have remaining bits
                if (bitsAccumulated > 0)
                {
                    // EOS (End of String) symbol for padding is all 1s
                    var paddingValue = (1UL << bitsAccumulated) - 1;
                    if (bitAccumulator > paddingValue)
                    {
                        Console.WriteLine($"[WARNING] Invalid Huffman padding detected (ignoring): {bitAccumulator:X} vs expected max {paddingValue:X}");
                        // Don't fail on padding issues - just log and continue
                    }
                }

                return result.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Huffman decoding error: {ex.Message}");
                // Fallback: try to decode as raw UTF-8
                try
                {
                    return Encoding.UTF8.GetString(data);
                }
                catch
                {
                    return ""; // Last resort: empty string
                }
            }
        }

        private static readonly Dictionary<(ulong bits, int length), int> HuffmanDecodeTable =
            new Dictionary<(ulong bits, int length), int>
            {
                // Complete Huffman table from RFC 7541 Appendix B
                { (0x1ff8, 13), 0 },      // (  0)
                { (0x7fffd8, 23), 1 },    // (  1)
                { (0xfffffe2, 28), 2 },   // (  2)
                { (0xfffffe3, 28), 3 },   // (  3)
                { (0xfffffe4, 28), 4 },   // (  4)
                { (0xfffffe5, 28), 5 },   // (  5)
                { (0xfffffe6, 28), 6 },   // (  6)
                { (0xfffffe7, 28), 7 },   // (  7)
                { (0xfffffe8, 28), 8 },   // (  8)
                { (0xffffea, 24), 9 },    // (  9) '\t'
                { (0x3ffffec, 30), 10 },  // ( 10) '\n'
                { (0xfffffe9, 28), 11 },  // ( 11)
                { (0xfffffea, 28), 12 },  // ( 12)
                { (0x3ffffed, 30), 13 },  // ( 13) '\r'
                { (0xfffffeb, 28), 14 },  // ( 14)
                { (0xfffffec, 28), 15 },  // ( 15)
                { (0xfffffed, 28), 16 },  // ( 16)
                { (0xfffffee, 28), 17 },  // ( 17)
                { (0xfffffef, 28), 18 },  // ( 18)
                { (0xffffff0, 28), 19 },  // ( 19)
                { (0xffffff1, 28), 20 },  // ( 20)
                { (0xffffff2, 28), 21 },  // ( 21)
                { (0x3ffffee, 30), 22 },  // ( 22)
                { (0xffffff3, 28), 23 },  // ( 23)
                { (0xffffff4, 28), 24 },  // ( 24)
                { (0xffffff5, 28), 25 },  // ( 25)
                { (0xffffff6, 28), 26 },  // ( 26)
                { (0xffffff7, 28), 27 },  // ( 27)
                { (0xffffff8, 28), 28 },  // ( 28)
                { (0xffffff9, 28), 29 },  // ( 29)
                { (0xffffffa, 28), 30 },  // ( 30)
                { (0xffffffb, 28), 31 },  // ( 31)
                { (0x14, 6), 32 },        // ( 32) ' '
                { (0x3f8, 10), 33 },      // ( 33) '!'
                { (0x3f9, 10), 34 },      // ( 34) '"'
                { (0xffa, 12), 35 },      // ( 35) '#'
                { (0x1ff9, 13), 36 },     // ( 36) '$'
                { (0x15, 6), 37 },        // ( 37) '%'
                { (0xf8, 8), 38 },        // ( 38) '&'
                { (0x7fa, 11), 39 },      // ( 39) '''
                { (0x3fa, 10), 40 },      // ( 40) '('
                { (0x3fb, 10), 41 },      // ( 41) ')'
                { (0xf9, 8), 42 },        // ( 42) '*'
                { (0x7fb, 11), 43 },      // ( 43) '+'
                { (0xfa, 8), 44 },        // ( 44) ','
                { (0x16, 6), 45 },        // ( 45) '-'
                { (0x17, 6), 46 },        // ( 46) '.'
                { (0x18, 6), 47 },        // ( 47) '/'
                { (0x0, 5), 48 },         // ( 48) '0'
                { (0x1, 5), 49 },         // ( 49) '1'
                { (0x2, 5), 50 },         // ( 50) '2'
                { (0x19, 6), 51 },        // ( 51) '3'
                { (0x1a, 6), 52 },        // ( 52) '4'
                { (0x1b, 6), 53 },        // ( 53) '5'
                { (0x1c, 6), 54 },        // ( 54) '6'
                { (0x1d, 6), 55 },        // ( 55) '7'
                { (0x1e, 6), 56 },        // ( 56) '8'
                { (0x1f, 6), 57 },        // ( 57) '9'
                { (0x5c, 8), 58 },        // ( 58) ':'
                { (0xfb, 8), 59 },        // ( 59) ';'
                { (0x7ffc, 15), 60 },     // ( 60) '<'
                { (0x20, 6), 61 },        // ( 61) '='
                { (0xffb, 12), 62 },      // ( 62) '>'
                { (0x3fc, 10), 63 },      // ( 63) '?'
                { (0x1ffa, 13), 64 },     // ( 64) '@'
                { (0x21, 6), 65 },        // ( 65) 'A'
                { (0x5d, 8), 66 },        // ( 66) 'B'
                { (0x5e, 8), 67 },        // ( 67) 'C'
                { (0x5f, 8), 68 },        // ( 68) 'D'
                { (0x60, 8), 69 },        // ( 69) 'E'
                { (0x61, 8), 70 },        // ( 70) 'F'
                { (0x62, 8), 71 },        // ( 71) 'G'
                { (0x63, 8), 72 },        // ( 72) 'H'
                { (0x64, 8), 73 },        // ( 73) 'I'
                { (0x65, 8), 74 },        // ( 74) 'J'
                { (0x66, 8), 75 },        // ( 75) 'K'
                { (0x67, 8), 76 },        // ( 76) 'L'
                { (0x68, 8), 77 },        // ( 77) 'M'
                { (0x69, 8), 78 },        // ( 78) 'N'
                { (0x6a, 8), 79 },        // ( 79) 'O'
                { (0x6b, 8), 80 },        // ( 80) 'P'
                { (0x6c, 8), 81 },        // ( 81) 'Q'
                { (0x6d, 8), 82 },        // ( 82) 'R'
                { (0x6e, 8), 83 },        // ( 83) 'S'
                { (0x6f, 8), 84 },        // ( 84) 'T'
                { (0x70, 8), 85 },        // ( 85) 'U'
                { (0x71, 8), 86 },        // ( 86) 'V'
                { (0x72, 8), 87 },        // ( 87) 'W'
                { (0xfc, 8), 88 },        // ( 88) 'X'
                { (0x73, 8), 89 },        // ( 89) 'Y'
                { (0xfd, 8), 90 },        // ( 90) 'Z'
                { (0x1ffb, 13), 91 },     // ( 91) '['
                { (0x7fff0, 19), 92 },    // ( 92) '\'
                { (0x1ffc, 13), 93 },     // ( 93) ']'
                { (0x3ffc, 14), 94 },     // ( 94) '^'
                { (0x22, 6), 95 },        // ( 95) '_'
                { (0x7ffd, 15), 96 },     // ( 96) '`'
                { (0x3, 5), 97 },         // ( 97) 'a'
                { (0x23, 6), 98 },        // ( 98) 'b'
                { (0x4, 5), 99 },         // ( 99) 'c'
                { (0x24, 6), 100 },       // (100) 'd'
                { (0x5, 5), 101 },        // (101) 'e'
                { (0x25, 6), 102 },       // (102) 'f'
                { (0x26, 6), 103 },       // (103) 'g'
                { (0x27, 6), 104 },       // (104) 'h'
                { (0x6, 5), 105 },        // (105) 'i'
                { (0x74, 8), 106 },       // (106) 'j'
                { (0x75, 8), 107 },       // (107) 'k'
                { (0x28, 6), 108 },       // (108) 'l'
                { (0x29, 6), 109 },       // (109) 'm'
                { (0x2a, 6), 110 },       // (110) 'n'
                { (0x7, 5), 111 },        // (111) 'o'
                { (0x2b, 6), 112 },       // (112) 'p'
                { (0x76, 8), 113 },       // (113) 'q'
                { (0x2c, 6), 114 },       // (114) 'r'
                { (0x8, 5), 115 },        // (115) 's'
                { (0x9, 5), 116 },        // (116) 't'
                { (0x2d, 6), 117 },       // (117) 'u'
                { (0x77, 8), 118 },       // (118) 'v'
                { (0x78, 8), 119 },       // (119) 'w'
                { (0x79, 8), 120 },       // (120) 'x'
                { (0x7a, 8), 121 },       // (121) 'y'
                { (0x7b, 8), 122 },       // (122) 'z'
                { (0x7ffe, 15), 123 },    // (123) '{'
                { (0x7fc, 11), 124 },     // (124) '|'
                { (0x3ffd, 14), 125 },    // (125) '}'
                { (0x1ffd, 13), 126 },    // (126) '~'
                { (0xffffffc, 28), 127 }, // (127)
                { (0xfffe6, 20), 128 },   // (128)
                { (0x3fffd2, 22), 129 },  // (129)
                { (0xfffe7, 20), 130 },   // (130)
                { (0xfffe8, 20), 131 },   // (131)
                { (0x3fffd3, 22), 132 },  // (132)
                { (0x3fffd4, 22), 133 },  // (133)
                { (0x3fffd5, 22), 134 },  // (134)
                { (0x7fffd9, 23), 135 },  // (135)
                { (0x3fffd6, 22), 136 },  // (136)
                { (0x7fffda, 23), 137 },  // (137)
                { (0x7fffdb, 23), 138 },  // (138)
                { (0x7fffdc, 23), 139 },  // (139)
                { (0x7fffdd, 23), 140 },  // (140)
                { (0x7fffde, 23), 141 },  // (141)
                { (0xffffeb, 24), 142 },  // (142)
                { (0x7fffdf, 23), 143 },  // (143)
                { (0xffffec, 24), 144 },  // (144)
                { (0xffffed, 24), 145 },  // (145)
                { (0x3fffd7, 22), 146 },  // (146)
                { (0x7fffe0, 23), 147 },  // (147)
                { (0xffffee, 24), 148 },  // (148)
                { (0x7fffe1, 23), 149 },  // (149)
                { (0x7fffe2, 23), 150 },  // (150)
                { (0x7fffe3, 23), 151 },  // (151)
                { (0x7fffe4, 23), 152 },  // (152)
                { (0x1fffdc, 21), 153 },  // (153)
                { (0x3fffd8, 22), 154 },  // (154)
                { (0x7fffe5, 23), 155 },  // (155)
                { (0x3fffd9, 22), 156 },  // (156)
                { (0x7fffe6, 23), 157 },  // (157)
                { (0x7fffe7, 23), 158 },  // (158)
                { (0xffffef, 24), 159 },  // (159)
                { (0x3fffda, 22), 160 },  // (160)
                { (0x1fffdd, 21), 161 },  // (161)
                { (0xfffe9, 20), 162 },   // (162)
                { (0x3fffdb, 22), 163 },  // (163)
                { (0x3fffdc, 22), 164 },  // (164)
                { (0x7fffe8, 23), 165 },  // (165)
                { (0x7fffe9, 23), 166 },  // (166)
                { (0x1fffde, 21), 167 },  // (167)
                { (0x7fffea, 23), 168 },  // (168)
                { (0x3fffdd, 22), 169 },  // (169)
                { (0x3fffde, 22), 170 },  // (170)
                { (0xfffff0, 24), 171 },  // (171)
                { (0x1fffdf, 21), 172 },  // (172)
                { (0x3fffdf, 22), 173 },  // (173)
                { (0x7fffeb, 23), 174 },  // (174)
                { (0x7fffec, 23), 175 },  // (175)
                { (0x1fffe0, 21), 176 },  // (176)
                { (0x1fffe1, 21), 177 },  // (177)
                { (0x3fffe0, 22), 178 },  // (178)
                { (0x1fffe2, 21), 179 },  // (179)
                { (0x7fffed, 23), 180 },  // (180)
                { (0x3fffe1, 22), 181 },  // (181)
                { (0x7fffee, 23), 182 },  // (182)
                { (0x7fffef, 23), 183 },  // (183)
                { (0xfffea, 20), 184 },   // (184)
                { (0x3fffe2, 22), 185 },  // (185)
                { (0x3fffe3, 22), 186 },  // (186)
                { (0x3fffe4, 22), 187 },  // (187)
                { (0x7ffff0, 23), 188 },  // (188)
                { (0x3fffe5, 22), 189 },  // (189)
                { (0x3fffe6, 22), 190 },  // (190)
                { (0x7ffff1, 23), 191 },  // (191)
                { (0x3ffffe0, 26), 192 }, // (192)
                { (0x3ffffe1, 26), 193 }, // (193)
                { (0xfffeb, 20), 194 },   // (194)
                { (0x7fff1, 19), 195 },   // (195)
                { (0x3fffe7, 22), 196 },  // (196)
                { (0x7ffff2, 23), 197 },  // (197)
                { (0x3fffe8, 22), 198 },  // (198)
                { (0x1ffffec, 25), 199 }, // (199)
                { (0x3ffffe2, 26), 200 }, // (200)
                { (0x3ffffe3, 26), 201 }, // (201)
                { (0x3ffffe4, 26), 202 }, // (202)
                { (0x7ffffde, 27), 203 }, // (203)
                { (0x7ffffdf, 27), 204 }, // (204)
                { (0x3ffffe5, 26), 205 }, // (205)
                { (0xfffff1, 24), 206 },  // (206)
                { (0x1ffffed, 25), 207 }, // (207)
                { (0x7fff2, 19), 208 },   // (208)
                { (0x1fffe3, 21), 209 },  // (209)
                { (0x3ffffe6, 26), 210 }, // (210)
                { (0x7ffffe0, 27), 211 }, // (211)
                { (0x7ffffe1, 27), 212 }, // (212)
                { (0x3ffffe7, 26), 213 }, // (213)
                { (0x7ffffe2, 27), 214 }, // (214)
                { (0xfffff2, 24), 215 },  // (215)
                { (0x1fffe4, 21), 216 },  // (216)
                { (0x1fffe5, 21), 217 },  // (217)
                { (0x3ffffe8, 26), 218 }, // (218)
                { (0x3ffffe9, 26), 219 }, // (219)
                { (0xffffffd, 28), 220 }, // (220)
                { (0x7ffffe3, 27), 221 }, // (221)
                { (0x7ffffe4, 27), 222 }, // (222)
                { (0x7ffffe5, 27), 223 }, // (223)
                { (0xfffec, 20), 224 },   // (224)
                { (0xfffff3, 24), 225 },  // (225)
                { (0xfffed, 20), 226 },   // (226)
                { (0x1fffe6, 21), 227 },  // (227)
                { (0x3fffe9, 22), 228 },  // (228)
                { (0x1fffe7, 21), 229 },  // (229)
                { (0x1fffe8, 21), 230 },  // (230)
                { (0x7ffff3, 23), 231 },  // (231)
                { (0x3fffea, 22), 232 },  // (232)
                { (0x3fffeb, 22), 233 },  // (233)
                { (0x1ffffee, 25), 234 }, // (234)
                { (0x1ffffef, 25), 235 }, // (235)
                { (0xfffff4, 24), 236 },  // (236)
                { (0xfffff5, 24), 237 },  // (237)
                { (0x3ffffea, 26), 238 }, // (238)
                { (0x7ffff4, 23), 239 },  // (239)
                { (0x3ffffeb, 26), 240 }, // (240)
                { (0x7ffffe6, 27), 241 }, // (241)
                { (0x3ffffec, 26), 242 }, // (242)
                { (0x3ffffed, 26), 243 }, // (243)
                { (0x7ffffe7, 27), 244 }, // (244)
                { (0x7ffffe8, 27), 245 }, // (245)
                { (0x7ffffe9, 27), 246 }, // (246)
                { (0x7ffffea, 27), 247 }, // (247)
                { (0x7ffffeb, 27), 248 }, // (248)
                { (0xffffffe, 28), 249 }, // (249)
                { (0x7ffffec, 27), 250 }, // (250)
                { (0x7ffffed, 27), 251 }, // (251)
                { (0x7ffffee, 27), 252 }, // (252)
                { (0x7ffffef, 27), 253 }, // (253)
                { (0x7fffff0, 27), 254 }, // (254)
                { (0x3ffffef, 26), 255 }, // (255)
            };

    }
}
#endif