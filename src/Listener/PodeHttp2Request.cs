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

                // Check connection preface
                if (!_hasReceivedPreface)
                {
                    Console.WriteLine($"[DEBUG] Checking connection preface, bytes.Length = {bytes.Length}");
                    if (!CheckConnectionPreface(bytes))
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
                    var remainingBytes = new byte[bytes.Length - HTTP2_PREFACE.Length];
                    Array.Copy(bytes, HTTP2_PREFACE.Length, remainingBytes, 0, remainingBytes.Length);
                    bytes = remainingBytes;
                    Console.WriteLine($"[DEBUG] Preface removed, remaining bytes: {remainingBytes.Length}");
                }

                // Add any incomplete frame data from previous parsing
                var allBytes = new List<byte>(_incompleteFrame);
                allBytes.AddRange(bytes);
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
                    try {
                        // Try to extract host without port
                        string hostOnly = Host;
                        if (Host.Contains(":")) {
                            hostOnly = Host.Split(':')[0];
                        }
                        
                        string fallbackUrl = $"{scheme}://{hostOnly}{path}";
                        Console.WriteLine($"[DEBUG] Trying fallback URL: {fallbackUrl}");
                        Url = new Uri(fallbackUrl);
                    }
                    catch (Exception innerEx) {
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
            Console.WriteLine($"[DEBUG] DecodeHeader: firstByte=0x{firstByte:X2}, offset={offset}");

            // Indexed Header Field (starts with 1)
            if ((firstByte & 0x80) != 0)
            {
                var index = DecodeInt(data, ref offset, 7);
                Console.WriteLine($"[DEBUG] Indexed header field: index={index}");
                if (StaticTable.ContainsKey(index))
                {
                    return StaticTable[index];
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
                }
                else if (StaticTable.ContainsKey(nameIndex))
                {
                    // Indexed name
                    name = StaticTable[nameIndex].Key;
                }
                else
                {
                    // Unknown index, skip
                    return null;
                }
                
                var value = DecodeLiteralString(data, ref offset);
                return new KeyValuePair<string, string>(name, value);
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
                }
                else if (StaticTable.ContainsKey(nameIndex))
                {
                    // Indexed name
                    name = StaticTable[nameIndex].Key;
                }
                else
                {
                    // Unknown index, skip
                    return null;
                }
                
                var value = DecodeLiteralString(data, ref offset);
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
                }
                else if (StaticTable.ContainsKey(nameIndex))
                {
                    // Indexed name
                    name = StaticTable[nameIndex].Key;
                }
                else
                {
                    // Unknown index, skip
                    return null;
                }
                
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

            var firstByte = data[offset];
            var isHuffmanCoded = (firstByte & 0x80) != 0;
            var length = firstByte & 0x7F;
            
            Console.WriteLine($"[DEBUG] DecodeLiteralString: offset={offset}, firstByte=0x{firstByte:X2}, isHuffmanCoded={isHuffmanCoded}, length={length}");
            offset++;
            
            if (offset + length > data.Length) 
            {
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Not enough bytes for string (need {length}, have {data.Length - offset})");
                return "";
            }

            // Only copy the exact number of bytes specified by length
            var stringBytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                stringBytes[i] = data[offset + i];
            }
            
            string result;
            if (isHuffmanCoded)
            {
                // For now, just decode as UTF-8 (proper Huffman decoding would be complex)
                result = Encoding.UTF8.GetString(stringBytes);
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Huffman coded string (decoded as UTF-8): '{result}'");
            }
            else
            {
                result = Encoding.UTF8.GetString(stringBytes);
                Console.WriteLine($"[DEBUG] DecodeLiteralString: Plain string: '{result}'");
            }
            
            Console.WriteLine($"[DEBUG] DecodeLiteralString: Raw bytes: {BitConverter.ToString(stringBytes)}");
            
            offset += length;
            Console.WriteLine($"[DEBUG] DecodeLiteralString: New offset={offset}");
            return result;
        }
    }
}
#endif