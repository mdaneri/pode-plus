#if !NETSTANDARD2_0
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Pode
{
    public class PodeHttp2Response : PodeResponse
    {
        // HTTP/2 Frame Types
        private const byte FRAME_TYPE_DATA = 0x0;
        private const byte FRAME_TYPE_HEADERS = 0x1;
        private const byte FRAME_TYPE_SETTINGS = 0x4;
        private const byte FRAME_TYPE_PING = 0x6;
        private const byte FRAME_TYPE_GOAWAY = 0x7;
        private const byte FRAME_TYPE_WINDOW_UPDATE = 0x8;

        // HTTP/2 Frame Flags
        private const byte FLAG_ACK = 0x1;
        private const byte FLAG_END_STREAM = 0x1;
        private const byte FLAG_END_HEADERS = 0x4;

        public int StreamId { get; set; }
        public SimpleHpackEncoder HpackEncoder { get; private set; }
        private readonly PodeContext _context;
        private bool _sentHeaders = false;
        private bool _sentBody = false;

        public PodeHttp2Response(PodeContext context) : base(context)
        {
            HpackEncoder = new SimpleHpackEncoder();
            _context = context;
        }

        /// <summary>
        /// Override the Send method to implement HTTP/2 binary framing
        /// Ensures HTTP/1.1 response is not sent
        /// </summary>
        public override async Task Send()
        {
            Console.WriteLine($"[DEBUG] HTTP/2 Send() method called - StreamId: {StreamId}, _sentHeaders: {_sentHeaders}, _sentBody: {_sentBody}, IsDisposed: {IsDisposed}, SseEnabled: {SseEnabled}");

            if ((_sentHeaders && _sentBody) || IsDisposed || (_sentHeaders && SseEnabled))
            {
                Console.WriteLine($"[DEBUG] HTTP/2 Send() returning early - already sent or disposed");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 Send() called but response already sent or disposed", _context.Listener, PodeLoggingLevel.Verbose, _context);
                return;
            }

            Console.WriteLine($"[DEBUG] HTTP/2 Response.Send() proceeding - StreamId: {StreamId}, StatusCode: {StatusCode}");
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 Response.Send() called - StreamId: {StreamId}, StatusCode: {StatusCode}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            try
            {
                Console.WriteLine($"[DEBUG] Setting SentHeaders and SentBody to true to prevent HTTP/1.1 response");
                // Mark headers and body as sent to prevent the base class Send() method
                // from sending HTTP/1.1 response
                SentHeaders = true;
                SentBody = true;

                Console.WriteLine($"[DEBUG] About to call SendHttp2Headers()");
                // Send HTTP/2 frames
                await SendHttp2Headers().ConfigureAwait(false);
                Console.WriteLine($"[DEBUG] SendHttp2Headers() completed, about to call SendHttp2Body()");
                await SendHttp2Body().ConfigureAwait(false);
                Console.WriteLine($"[DEBUG] SendHttp2Body() completed successfully");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 response sent successfully", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }
            catch (OperationCanceledException ex)
            {
                Console.WriteLine($"[DEBUG] OperationCanceledException in Send(): {ex.Message}");
            }
            catch (IOException ex)
            {
                Console.WriteLine($"[DEBUG] IOException in Send(): {ex.Message}");
            }
            catch (AggregateException aex)
            {
                Console.WriteLine($"[DEBUG] AggregateException in Send(): {aex.Message}");
                PodeHelpers.HandleAggregateException(aex, _context.Listener);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Exception in Send(): {ex.GetType().Name}: {ex.Message}");
                PodeHelpers.WriteErrorMessage($"DEBUG: Exception in HTTP/2 Send(): {ex.Message}", _context.Listener, PodeLoggingLevel.Verbose, _context);
                PodeHelpers.WriteException(ex, _context.Listener);
                throw;
            }
            finally
            {
                Console.WriteLine($"[DEBUG] Finally block in Send(), about to call Flush()");
                await Flush().ConfigureAwait(false);
                Console.WriteLine($"[DEBUG] Flush() completed");
            }
        }

        private async Task SendHttp2Headers()
        {
            Console.WriteLine($"[DEBUG] SendHttp2Headers() called - _sentHeaders: {_sentHeaders}");
            if (_sentHeaders)
            {
                Console.WriteLine($"[DEBUG] SendHttp2Headers() returning early - headers already sent");
                return;
            }

            Console.WriteLine($"[DEBUG] Sending HTTP/2 headers - StreamId: {StreamId}, StatusCode: {StatusCode}");
            PodeHelpers.WriteErrorMessage($"DEBUG: Sending HTTP/2 headers - StreamId: {StreamId}, StatusCode: {StatusCode}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            // Build HTTP/2 headers frame
            var headers = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>(":status", StatusCode.ToString())
            };

            // Add regular headers
            foreach (string key in Headers.Keys)
            {
                var value = Headers[key];
                if (!string.IsNullOrEmpty(value?.ToString()))
                {
                    headers.Add(new KeyValuePair<string, string>(key.ToLower(), value.ToString()));
                    Console.WriteLine($"[DEBUG] Added header: {key.ToLower()} = {value}");
                }
            }

            // Ensure content-type is always present
            bool hasContentType = false;
            if (!string.IsNullOrEmpty(ContentType))
            {
                headers.Add(new KeyValuePair<string, string>("content-type", ContentType));
                Console.WriteLine($"[DEBUG] Added content-type header: {ContentType}");
                hasContentType = true;
            }
            else
            {
                // Check if content-type was added via Headers
                foreach (var header in headers)
                {
                    if (header.Key.ToLower() == "content-type")
                    {
                        hasContentType = true;
                        break;
                    }
                }
            }

            // Add default content-type if none specified
            if (!hasContentType)
            {
                headers.Add(new KeyValuePair<string, string>("content-type", "text/html; charset=utf-8"));
                Console.WriteLine($"[DEBUG] Added default content-type header: text/html; charset=utf-8");
            }

            // Add content-length if body is present
            if (StatusCode != 204 && StatusCode != 304) // Not No Content or Not Modified
            {
                bool hasContentLength = false;
                foreach (var header in headers)
                {
                    if (header.Key.ToLower() == "content-length")
                    {
                        hasContentLength = true;
                        break;
                    }
                }

                if (!hasContentLength)
                {
                    // Estimate content length (will be updated when body is sent)
                    var contentLength = 0;
                    if (!string.IsNullOrEmpty(ContentType) && ContentType.Contains("html"))
                    {
                        contentLength = 100; // Default for HTML responses
                    }
                    headers.Add(new KeyValuePair<string, string>("content-length", contentLength.ToString()));
                    Console.WriteLine($"[DEBUG] Added default content-length header: {contentLength}");
                }
            }

            Console.WriteLine($"[DEBUG] HTTP/2 headers count: {headers.Count}");
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 headers count: {headers.Count}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            // Encode headers with HPACK
            Console.WriteLine($"[DEBUG] About to encode headers with HPACK");
            var encodedHeaders = HpackEncoder.Encode(headers);
            Console.WriteLine($"[DEBUG] Encoded headers length: {encodedHeaders.Length}");
            PodeHelpers.WriteErrorMessage($"DEBUG: Encoded headers length: {encodedHeaders.Length}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            // Send HEADERS frame
            Console.WriteLine($"[DEBUG] About to send HEADERS frame");
            await SendFrame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, StreamId, encodedHeaders);
            Console.WriteLine($"[DEBUG] HEADERS frame sent successfully");
            _sentHeaders = true;
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 headers sent successfully", _context.Listener, PodeLoggingLevel.Verbose, _context);
        }

        private async Task SendHttp2Body()
        {
            Console.WriteLine($"[DEBUG] SendHttp2Body() called - _sentBody: {_sentBody}");
            if (_sentBody)
            {
                Console.WriteLine($"[DEBUG] SendHttp2Body() returning early - body already sent");
                return;
            }

            Console.WriteLine($"[DEBUG] Sending HTTP/2 body - StreamId: {StreamId}");
            PodeHelpers.WriteErrorMessage($"DEBUG: Sending HTTP/2 body - StreamId: {StreamId}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            byte[] data = null;
            if (OutputStream != null && OutputStream.Length > 0)
            {
                data = OutputStream.ToArray();
                Console.WriteLine($"[DEBUG] HTTP/2 body data length: {data.Length}");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 body data length: {data.Length}", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }

            if (data != null && data.Length > 0)
            {
                Console.WriteLine($"[DEBUG] About to send DATA frame with {data.Length} bytes");
                // Send DATA frame with END_STREAM flag
                await SendFrame(FRAME_TYPE_DATA, FLAG_END_STREAM, StreamId, data);
                Console.WriteLine($"[DEBUG] DATA frame sent successfully with {data.Length} bytes");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 DATA frame sent with {data.Length} bytes", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }
            else
            {
                Console.WriteLine($"[DEBUG] About to send empty DATA frame");
                // Send empty DATA frame with END_STREAM flag
                await SendFrame(FRAME_TYPE_DATA, FLAG_END_STREAM, StreamId, new byte[0]);
                Console.WriteLine($"[DEBUG] Empty DATA frame sent successfully");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 empty DATA frame sent", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }

            _sentBody = true;
            Console.WriteLine($"[DEBUG] HTTP/2 body sending completed successfully");
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 body sent successfully", _context.Listener, PodeLoggingLevel.Verbose, _context);
        }

        private async Task SendFrame(byte type, byte flags, int streamId, byte[] payload)
        {
            PodeHelpers.WriteErrorMessage($"DEBUG: Sending HTTP/2 frame - Type: {type}, Flags: {flags}, StreamId: {streamId}, PayloadLength: {payload?.Length ?? 0}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            var frameHeader = new byte[9];
            var length = payload?.Length ?? 0;

            // Frame length (24 bits)
            frameHeader[0] = (byte)((length >> 16) & 0xFF);
            frameHeader[1] = (byte)((length >> 8) & 0xFF);
            frameHeader[2] = (byte)(length & 0xFF);

            // Frame type
            frameHeader[3] = type;

            // Flags
            frameHeader[4] = flags;

            // Stream ID (31 bits, R bit is reserved)
            frameHeader[5] = (byte)((streamId >> 24) & 0x7F);
            frameHeader[6] = (byte)((streamId >> 16) & 0xFF);
            frameHeader[7] = (byte)((streamId >> 8) & 0xFF);
            frameHeader[8] = (byte)(streamId & 0xFF);

            // Get the underlying network stream
            var networkStream = GetNetworkStream();
            if (networkStream != null)
            {
                PodeHelpers.WriteErrorMessage($"DEBUG: Writing frame header and payload to network stream", _context.Listener, PodeLoggingLevel.Verbose, _context);

                // Send frame header
                await networkStream.WriteAsync(frameHeader, 0, frameHeader.Length);

                // Send payload if present
                if (payload != null && payload.Length > 0)
                {
                    await networkStream.WriteAsync(payload, 0, payload.Length);
                }

                await networkStream.FlushAsync();
                PodeHelpers.WriteErrorMessage($"DEBUG: Frame sent successfully", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }
            else
            {
                PodeHelpers.WriteErrorMessage($"DEBUG: Network stream is null - cannot send frame", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }
        }

        private Stream GetNetworkStream()
        {
            try
            {
                // For HTTP/2, use the existing input stream from the request
                // This is crucial because:
                // 1. For SSL/TLS connections, this is the SslStream that handles encryption
                // 2. Creating a new NetworkStream bypasses SSL encryption
                // 3. The client expects encrypted HTTP/2 frames
                var stream = _context.Request?.InputStream;
                if (stream != null)
                {
                    PodeHelpers.WriteErrorMessage($"DEBUG: Using existing input stream type: {stream.GetType().Name}", _context.Listener, PodeLoggingLevel.Verbose, _context);
                    return stream;
                }

                PodeHelpers.WriteErrorMessage($"DEBUG: No input stream available", _context.Listener, PodeLoggingLevel.Verbose, _context);
                return null;
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, _context.Listener);
                return null;
            }
        }

        public async Task SendSettingsFrame(Dictionary<string, object> settings = null)
        {
            var payload = new List<byte>();

            if (settings != null)
            {
                foreach (var setting in settings)
                {
                    var settingId = GetSettingId(setting.Key);
                    if (settingId > 0)
                    {
                        var value = Convert.ToUInt32(setting.Value);

                        // Setting ID (2 bytes)
                        payload.Add((byte)((settingId >> 8) & 0xFF));
                        payload.Add((byte)(settingId & 0xFF));

                        // Setting Value (4 bytes)
                        payload.Add((byte)((value >> 24) & 0xFF));
                        payload.Add((byte)((value >> 16) & 0xFF));
                        payload.Add((byte)((value >> 8) & 0xFF));
                        payload.Add((byte)(value & 0xFF));
                    }
                }
            }

            await SendFrame(FRAME_TYPE_SETTINGS, 0, 0, payload.ToArray());
        }

        public async Task SendSettingsAck()
        {
            await SendFrame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, new byte[0]);
        }

        /// <summary>
        /// Override WriteBody to handle HTTP/2 framing properly
        /// </summary>
        public override void WriteBody(byte[] bytes, long[] ranges = null, PodeCompressionType compression = PodeCompressionType.none)
        {
            Console.WriteLine($"[DEBUG] HTTP/2 WriteBody called - StreamId: {StreamId}, bytes: {bytes?.Length ?? 0}, ranges: {ranges?.Length ?? 0}, compression: {compression}");
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 WriteBody called with {bytes?.Length ?? 0} bytes, StreamId: {StreamId}", _context.Listener, PodeLoggingLevel.Verbose, _context);

            // Prevent duplicate response sending
            if (_sentHeaders && _sentBody)
            {
                Console.WriteLine($"[DEBUG] HTTP/2 response already sent, ignoring duplicate WriteBody call");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 response already sent, ignoring duplicate WriteBody call", _context.Listener, PodeLoggingLevel.Verbose, _context);
                return;
            }

            Console.WriteLine($"[DEBUG] About to store {bytes?.Length ?? 0} bytes in OutputStream");
            // Store the body data in the OutputStream
            if (bytes != null && bytes.Length > 0)
            {
                OutputStream.Write(bytes, 0, bytes.Length);
                Console.WriteLine($"[DEBUG] Stored {bytes.Length} bytes in OutputStream, new length: {OutputStream.Length}");
            }

            Console.WriteLine($"[DEBUG] About to call Send() method for HTTP/2 response");
            // Send the HTTP/2 response using the Send method
            Send().GetAwaiter().GetResult();
            Console.WriteLine($"[DEBUG] Send() method completed for HTTP/2 response");
        }

        /// <summary>
        /// Override WriteBody to handle HTTP/2 framing properly
        /// </summary>
        public override void WriteBody(byte[] bytes, PodeCompressionType compression = PodeCompressionType.none)
        {
            WriteBody(bytes, null, compression);
        }

        public async Task SendPingResponse(byte[] pingData)
        {
            await SendFrame(FRAME_TYPE_PING, FLAG_ACK, 0, pingData);
        }

        public async Task SendGoAway(int lastStreamId, uint errorCode, byte[] debugData = null)
        {
            var payload = new List<byte>();

            // Last Stream ID (4 bytes)
            payload.Add((byte)((lastStreamId >> 24) & 0x7F));
            payload.Add((byte)((lastStreamId >> 16) & 0xFF));
            payload.Add((byte)((lastStreamId >> 8) & 0xFF));
            payload.Add((byte)(lastStreamId & 0xFF));

            // Error Code (4 bytes)
            payload.Add((byte)((errorCode >> 24) & 0xFF));
            payload.Add((byte)((errorCode >> 16) & 0xFF));
            payload.Add((byte)((errorCode >> 8) & 0xFF));
            payload.Add((byte)(errorCode & 0xFF));

            // Debug data (optional)
            if (debugData != null)
            {
                payload.AddRange(debugData);
            }

            await SendFrame(FRAME_TYPE_GOAWAY, 0, 0, payload.ToArray());
        }

        private int GetSettingId(string settingName)
        {
            switch (settingName)
            {
                case "SETTINGS_HEADER_TABLE_SIZE":
                    return 1;
                case "SETTINGS_ENABLE_PUSH":
                    return 2;
                case "SETTINGS_MAX_CONCURRENT_STREAMS":
                    return 3;
                case "SETTINGS_INITIAL_WINDOW_SIZE":
                    return 4;
                case "SETTINGS_MAX_FRAME_SIZE":
                    return 5;
                case "SETTINGS_MAX_HEADER_LIST_SIZE":
                    return 6;
                default:
                    return 0;
            }
        }

        /// <summary>
        /// Prevent the HTTP/1.1 headers and body from being sent in Send() method
        /// by providing custom implementations that do nothing
        /// </summary>
        private Task SendHeaders(bool timeout)
        {
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 SendHeaders is no-op, headers will be sent via frames", _context.Listener, PodeLoggingLevel.Verbose, _context);
            // Do nothing - HTTP/2 headers are sent via HEADERS frames in SendHttp2Headers
            return Task.CompletedTask;
        }

        /// <summary>
        /// Prevent the HTTP/1.1 body from being sent in Send() method
        /// by providing a custom implementation that does nothing
        /// </summary>
        private Task SendBody(bool timeout)
        {
            PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 SendBody is no-op, body will be sent via frames", _context.Listener, PodeLoggingLevel.Verbose, _context);
            // Do nothing - HTTP/2 body is sent via DATA frames in SendHttp2Body
            return Task.CompletedTask;
        }
    }

    // Simplified HPACK encoder
    public class SimpleHpackEncoder
    {
        private static readonly Dictionary<KeyValuePair<string, string>, int> StaticTable =
            new Dictionary<KeyValuePair<string, string>, int>
            {
                { new KeyValuePair<string, string>(":authority", ""), 1 },
                { new KeyValuePair<string, string>(":method", "GET"), 2 },
                { new KeyValuePair<string, string>(":method", "POST"), 3 },
                { new KeyValuePair<string, string>(":path", "/"), 4 },
                { new KeyValuePair<string, string>(":path", "/index.html"), 5 },
                { new KeyValuePair<string, string>(":scheme", "http"), 6 },
                { new KeyValuePair<string, string>(":scheme", "https"), 7 },
                { new KeyValuePair<string, string>(":status", "200"), 8 },
                { new KeyValuePair<string, string>(":status", "204"), 9 },
                { new KeyValuePair<string, string>(":status", "206"), 10 },
                { new KeyValuePair<string, string>(":status", "304"), 11 },
                { new KeyValuePair<string, string>(":status", "400"), 12 },
                { new KeyValuePair<string, string>(":status", "404"), 13 },
                { new KeyValuePair<string, string>(":status", "500"), 14 }
            };

        public byte[] Encode(List<KeyValuePair<string, string>> headers)
        {
            var encoded = new List<byte>();

            foreach (var header in headers)
            {
                var headerPair = new KeyValuePair<string, string>(header.Key.ToLower(), header.Value);

                // Check if header is in static table
                if (StaticTable.ContainsKey(headerPair))
                {
                    var index = StaticTable[headerPair];
                    encoded.Add((byte)(0x80 | index)); // Indexed header field
                }
                else
                {
                    // Literal header field with incremental indexing
                    encoded.Add(0x40); // 01000000

                    // Encode name
                    var nameBytes = Encoding.UTF8.GetBytes(header.Key.ToLower());
                    encoded.Add((byte)nameBytes.Length);
                    encoded.AddRange(nameBytes);

                    // Encode value
                    var valueBytes = Encoding.UTF8.GetBytes(header.Value);
                    encoded.Add((byte)valueBytes.Length);
                    encoded.AddRange(valueBytes);
                }
            }

            return encoded.ToArray();
        }
    }
}
#endif
