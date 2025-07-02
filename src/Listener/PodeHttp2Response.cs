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
        /// </summary>
        public new async Task Send()
        {
            if ((_sentHeaders && _sentBody) || IsDisposed || (_sentHeaders && SseEnabled))
            {
                return;
            }

            PodeHelpers.WriteErrorMessage($"Sending HTTP/2 response", _context.Listener, PodeLoggingLevel.Verbose, _context);

            try
            {
                await SendHttp2Headers().ConfigureAwait(false);
                await SendHttp2Body().ConfigureAwait(false);
                PodeHelpers.WriteErrorMessage($"HTTP/2 response sent", _context.Listener, PodeLoggingLevel.Verbose, _context);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (AggregateException aex)
            {
                PodeHelpers.HandleAggregateException(aex, _context.Listener);
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, _context.Listener);
                throw;
            }
            finally
            {
                await Flush().ConfigureAwait(false);
            }
        }

        private async Task SendHttp2Headers()
        {
            if (_sentHeaders) return;

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
                }
            }

            // Encode headers with HPACK
            var encodedHeaders = HpackEncoder.Encode(headers);

            // Send HEADERS frame
            await SendFrame(FRAME_TYPE_HEADERS, FLAG_END_HEADERS, StreamId, encodedHeaders);
            _sentHeaders = true;
        }

        private async Task SendHttp2Body()
        {
            if (_sentBody) return;

            byte[] data = null;
            if (OutputStream != null && OutputStream.Length > 0)
            {
                data = OutputStream.ToArray();
            }

            if (data != null && data.Length > 0)
            {
                // Send DATA frame with END_STREAM flag
                await SendFrame(FRAME_TYPE_DATA, FLAG_END_STREAM, StreamId, data);
            }
            else
            {
                // Send empty DATA frame with END_STREAM flag
                await SendFrame(FRAME_TYPE_DATA, FLAG_END_STREAM, StreamId, new byte[0]);
            }

            _sentBody = true;
        }

        private async Task SendFrame(byte type, byte flags, int streamId, byte[] payload)
        {
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
                // Send frame header
                await networkStream.WriteAsync(frameHeader, 0, frameHeader.Length);

                // Send payload if present
                if (payload != null && payload.Length > 0)
                {
                    await networkStream.WriteAsync(payload, 0, payload.Length);
                }

                await networkStream.FlushAsync();
            }
        }

        private Stream GetNetworkStream()
        {
            // Access the underlying network stream through the context
            return _context.Request?.InputStream;
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
