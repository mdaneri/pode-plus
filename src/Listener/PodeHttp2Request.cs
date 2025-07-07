#if !NETSTANDARD2_0
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Net.Security;
using System.Buffers.Binary;
using hpack;

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
        private const int DEFAULT_WINDOW_SIZE = 65_535; // Default connection window size (RFC 7540 §6.9)

        // HTTP/2 Connection Preface
        private static readonly byte[] HTTP2_PREFACE = System.Text.Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // RFC 7540 §7 – Error codes
        public enum Http2ErrorCode : uint
        {
            NoError = 0x0,
            ProtocolError = 0x1,
            InternalError = 0x2,
            FlowControlError = 0x3,
            SettingsTimeout = 0x4,
            StreamClosed = 0x5,
            FrameSizeError = 0x6,
            RefusedStream = 0x7,
            Cancel = 0x8,
            CompressionError = 0x9,
            ConnectError = 0xA,
            EnhanceYourCalm = 0xB,
            InadequateSecurity = 0xC,
            Http11Required = 0xD
        }


        // HTTP/2 Properties

        private int _connectionWindowSize = DEFAULT_WINDOW_SIZE;
        public string HttpMethod { get; private set; }
        public NameValueCollection QueryString { get; private set; }
        public string Protocol { get; private set; } = "HTTP/2.0";
        public string ProtocolVersion { get; private set; } = "2.0";
        internal int PeerMaxFrameSize { get; private set; } = 16384; // default 2^14
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
        private readonly hpack.Decoder _hpackDecoder;
        private readonly TaskCompletionSource<bool> _settingsTcs;



        // Helper to collect decoded headers from hpack.Decoder
        private sealed class ListHeaderListener : hpack.IHeaderListener
        {
            public readonly List<(string Name, string Value)> Headers = new List<(string Name, string Value)>();
            public void AddHeader(byte[] name, byte[] value, bool sensitive)
                => Headers.Add((System.Text.Encoding.UTF8.GetString(name), System.Text.Encoding.UTF8.GetString(value)));
        }
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
            get => StreamId != 0 && !IsHttpMethodValid();
        }

        // A request becomes “processable” only once we have complete headers.
        public override bool IsProcessable
        {
            get => StreamId != 0 &&
           !CloseImmediately &&
           !AwaitingBody &&
           _isHeadersComplete;
        }

        public PodeHttp2Request(Socket socket, PodeSocket podeSocket, PodeContext context)
            : base(socket, podeSocket, context)
        {
            Console.WriteLine("[DEBUG] PodeHttp2Request constructor called");
            Type = PodeProtocolType.Http;
            Streams = new Dictionary<int, Http2Stream>();
            Settings = new Dictionary<string, object>();
            _hpackDecoder = new hpack.Decoder(maxHeaderSize: 8192, maxHeaderTableSize: 4096);
            _incompleteFrame = new List<byte>();
            ContentEncoding = System.Text.Encoding.UTF8;
            _settingsTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
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
            Console.WriteLine($"[DEBUG] ValidateInput called with {bytes.Length} bytes, hasReceivedPreface={_hasReceivedPreface}");
            if (bytes.Length > 0)
            {
                Console.WriteLine($"[DEBUG] ValidateInput bytes: {BitConverter.ToString(bytes.Take(Math.Min(32, bytes.Length)).ToArray()).Replace("-", " ")}");
            }

            if (bytes.Length == 0)
            {
                Console.WriteLine("[DEBUG] ValidateInput: bytes.Length == 0, returning false");
                return false;
            }

            // Check for HTTP/2 connection preface first
            if (!_hasReceivedPreface)
            {
                // If we have stored preface data from HTTP/1.1 parser, we can accept any valid HTTP/2 frame
                if (Context.Data.ContainsKey("Http2PrefaceData"))
                {
                    Console.WriteLine($"[DEBUG] ValidateInput: Found stored preface data, accepting incoming {bytes.Length} bytes as HTTP/2 frames");
                    if (_incompleteFrame.Count > 0)
                        return bytes.Length > 0;   // we’re finishing a half-read frame
                    return bytes.Length >= 9;      // fresh frame header

                }

                var result = bytes.Length >= HTTP2_PREFACE.Length;
                Console.WriteLine($"[DEBUG] ValidateInput: checking preface length {bytes.Length} >= {HTTP2_PREFACE.Length}, result={result}");
                return result;
            }

            // For HTTP/2, we need at least 9 bytes for a frame header
            //   var frameResult = bytes.Length >= 9;
            //   Console.WriteLine($"[DEBUG] ValidateInput: checking frame length {bytes.Length} >= 9, result={frameResult}");
            //   return frameResult;

            // After the connection preface:
            //   • if we’re starting a *new* frame   → need ≥9 bytes (header),
            //   • if we already hold an incomplete header/payload in _incompleteFrame
            //     → *any* positive length lets us finish it.
            if (_incompleteFrame.Count > 0)
            {
                Console.WriteLine("[DEBUG] ValidateInput: continuing incomplete frame");
                return bytes.Length > 0;
            }

            bool frameOk = bytes.Length >= 9;
            Console.WriteLine($"[DEBUG] ValidateInput: checking frame length {bytes.Length} ≥ 9, result={frameOk}");
            return frameOk;
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
            if (bytes.Length > 0)
            {
                Console.WriteLine($"[DEBUG] First 16 bytes: {BitConverter.ToString(bytes.Take(Math.Min(16, bytes.Length)).ToArray()).Replace("-", " ")}");
            }

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
                bool usingStoredPreface = false;
                if (!_hasReceivedPreface && Context.Data.ContainsKey("Http2PrefaceData"))
                {
                    var prefaceData = (byte[])Context.Data["Http2PrefaceData"];
                    Console.WriteLine($"[DEBUG] Using stored preface data ({prefaceData.Length} bytes) instead of reading from stream");
                    actualBytes = prefaceData;
                    usingStoredPreface = true;
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

                    // If we used stored preface data, also process the original bytes from this Parse call
                    /*   if (usingStoredPreface && bytes.Length > 0)
                       {
                           Console.WriteLine($"[DEBUG] Processing original {bytes.Length} bytes after handling stored preface");
                           // Combine the original bytes with the remaining bytes after preface
                           //    actualBytes = actualBytes.Concat(bytes.Skip(HTTP2_PREFACE.Length)).ToArray();

                           var combinedBytes = new List<byte>(actualBytes);
                           combinedBytes.AddRange(bytes);
                           actualBytes = combinedBytes.ToArray();

                           Console.WriteLine($"[DEBUG] Combined data length: {actualBytes.Length}");
                       }*/
                    if (usingStoredPreface)
                    {
                        int prefaceLen = HTTP2_PREFACE.Length;       // 24 bytes
                        int surplusLen = bytes.Length - prefaceLen;  // >0 means extra data arrived

                        if (surplusLen > 0)
                        {
                            var extra = new byte[surplusLen];
                            System.Buffer.BlockCopy(bytes, prefaceLen, extra, 0, surplusLen);

                            // append once, no duplicates
                            actualBytes = actualBytes
                                .Concat(extra)      // needs `using System.Linq;`
                                .ToArray();

                            Console.WriteLine($"[DEBUG] Appended {surplusLen} extra byte(s) that followed the preface");
                        }

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
                        //   _incompleteFrame.Clear(); // Clear old junk to avoid misalignment
                        // Save incomplete frame for next parse
                        //   _incompleteFrame.AddRange(allBytes.GetRange(offset, allBytes.Count - offset));
                        _incompleteFrame.Clear();
                        _incompleteFrame.AddRange(allBytes.Skip(offset));  // keep remainder
                        break;
                    }
                    var frameStartOffset = offset; // Store the original offset before parsing

                    var frame = PodeHttp2Request.ParseFrame(allBytes.ToArray(), ref offset);
                    if (frame == null)
                    {
                        Console.WriteLine("[DEBUG] Incomplete frame detected, need more data");
                        // Incomplete frame, save for next parse - use the original frame start offset
                        var remainingBytes = allBytes.Count - frameStartOffset;
                        if (remainingBytes > 0)
                        {
                            Console.WriteLine($"[DEBUG] Incomplete frame detected, saving {remainingBytes} bytes for next parse");
                            //                            _incompleteFrame.AddRange(allBytes.GetRange(frameStartOffset, remainingBytes));
                            //         _incompleteFrame.Clear();   // old junk would break alignment
                            _incompleteFrame.AddRange(allBytes.GetRange(frameStartOffset, remainingBytes));
                        }
                        break; // Exit the loop, we need more data
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

        private static Http2Frame ParseFrame(IReadOnlyList<byte> buf, ref int offset)
        {
            if (buf.Count - offset < 9) return null;

            int len = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
            byte type = buf[offset + 3];
            byte flags = buf[offset + 4];
            int stream = ((buf[offset + 5] & 0x7F) << 24) |
                          (buf[offset + 6] << 16) |
                          (buf[offset + 7] << 8) |
                           buf[offset + 8];

            if (buf.Count - (offset + 9) < len) return null;

            var payload = new byte[len];
            for (int i = 0; i < len; i++) payload[i] = buf[offset + 9 + i];

            offset += 9 + len;

            Console.WriteLine($"[DEBUG] ParseFrame: T=0x{type:X2} F=0x{flags:X2} SID={stream} Len={len}");
            return new Http2Frame
            {
                Length = len,
                Type = type,
                Flags = flags,
                StreamId = stream,
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
                    await ProcessSettingsFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_PRIORITY:
                    Console.WriteLine("[DEBUG] Processing PRIORITY frame");
                    await ProcessPriorityFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_RST_STREAM:
                    Console.WriteLine("[DEBUG] Processing RST_STREAM frame");
                    await ProcessRstStreamFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_PING:
                    Console.WriteLine("[DEBUG] Processing PING frame");
                    await ProcessPingFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_GOAWAY:
                    Console.WriteLine("[DEBUG] Processing GOAWAY frame");
                    ProcessGoAwayFrame(frame, cancellationToken);
                    break;
                case FRAME_TYPE_WINDOW_UPDATE:
                    Console.WriteLine("[DEBUG] Processing WINDOW_UPDATE frame");
                    await ProcessWindowUpdateFrame(frame, cancellationToken);
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

        private async Task ProcessHeadersFrame(Http2Frame frame,
                                        CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] ProcessHeadersFrame: StreamId={frame.StreamId}, Length={frame.Length}, Flags=0x{frame.Flags:X2}");

            StreamId = frame.StreamId;
            EndOfHeaders = (frame.Flags & FLAG_END_HEADERS) != 0;
            EndOfStream = (frame.Flags & FLAG_END_STREAM) != 0;

            Console.WriteLine($"[DEBUG] EndOfHeaders={EndOfHeaders}, EndOfStream={EndOfStream}");

            // Get-or-create stream entry (same pattern you already use)
            if (!Streams.ContainsKey(StreamId))
            {
                Streams[StreamId] = new Http2Stream(StreamId, (int)Settings["SETTINGS_INITIAL_WINDOW_SIZE"]);
            }
            var stream = Streams[StreamId];

            // Debug: Show raw header payload
            Console.WriteLine($"[DEBUG] Raw header payload ({frame.Payload.Length} bytes): {BitConverter.ToString(frame.Payload).Replace("-", " ")}");

            // ---------- strip PADDED / PRIORITY and feed HPACK ----------
            int offset = 0;
            int padLen = 0;

            if ((frame.Flags & FLAG_PADDED) != 0)
            {
                padLen = frame.Payload[offset];
                offset += 1;
            }

            if ((frame.Flags & FLAG_PRIORITY) != 0)
            {
                offset += 5;            // 4-byte stream-dependency + 1-byte weight
            }

            int blockLen = frame.Payload.Length - offset - padLen;
            if (blockLen < 0) blockLen = 0;   // safety guard

            var headerListener = new ListHeaderListener();

            try
            {
                using (var ms = new MemoryStream(frame.Payload, offset, blockLen))
                using (var br = new BinaryReader(ms, System.Text.Encoding.UTF8, leaveOpen: true))
                {
                    _hpackDecoder.Decode(br, headerListener);
                    if (EndOfHeaders)
                        _hpackDecoder.EndHeaderBlock();
                }

                Console.WriteLine($"[DEBUG] Decoded {headerListener.Headers.Count} headers from HPACK:");
                foreach (var (name, value) in headerListener.Headers)
                {
                    stream.Headers[name] = value;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] HPACK decode failed: {ex.Message} → sending RST_STREAM");
                await SendRstStream(frame.StreamId, 0x1);   // PROTOCOL_ERROR
                return;                                     // stop processing this stream
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

        // ---------------------------------------------------------------
        //  Low-level frame writer (request side)
        //
        //  NOTE: very similar to the version in PodeHttp2Response, but we
        //  keep it local so the request can send RST_STREAM when needed.
        // ---------------------------------------------------------------
        public async Task SendFrame(byte type, byte flags, int streamId, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
        {
            var stream = GetNetworkStream();
            if (stream == null || !stream.CanWrite)
            {
                Console.WriteLine("[DEBUG] SendFrame: network stream unavailable");
                return;
            }

            Console.WriteLine($"[DEBUG] SendFrame: Type=0x{type:X2}, Flags=0x{flags:X2}, StreamId={streamId}, PayloadLength={payload.Length}");

            int length = payload.Length;
            if (length > 0xFFFFFF)
                throw new ArgumentOutOfRangeException(nameof(payload), "Frame larger than 16 MB");

            // --- build 9-byte header ------------------------------------------------
            var header = new byte[9];

            header[0] = (byte)((length >> 16) & 0xFF);
            header[1] = (byte)((length >> 8) & 0xFF);
            header[2] = (byte)(length & 0xFF);

            header[3] = type;
            header[4] = flags;

            int sid31 = streamId & 0x7FFF_FFFF;        // clear the reserved R-bit
            header[5] = (byte)((sid31 >> 24) & 0xFF);
            header[6] = (byte)((sid31 >> 16) & 0xFF);
            header[7] = (byte)((sid31 >> 8) & 0xFF);
            header[8] = (byte)(sid31 & 0xFF);

            // --- single buffer so header+payload leave in one TLS record -----------
            byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(9 + length);
            try
            {
                System.Buffer.BlockCopy(header, 0, buffer, 0, 9);

                if (length != 0)
                {
                    // fast path when the payload is already backed by an array
                    if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(
                            payload, out ArraySegment<byte> seg))
                    {
                        System.Buffer.BlockCopy(seg.Array, seg.Offset, buffer, 9, length);
                    }
                    else
                    {
                        // fallback (rare) – copy via Span
                        payload.Span.CopyTo(buffer.AsSpan(9, length));
                    }
                }

                await stream.WriteAsync(buffer.AsMemory(0, 9 + length), ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);

                Console.WriteLine(
                    $"[DEBUG] Sent frame: T=0x{type:X2} F=0x{flags:X2} SID={streamId} Len={length}");
            }
            finally
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
            }
        }


        /// <summary>Send a DATA payload respecting both flow-control windows.</summary>
        /// returns true if at least one DATA frame was sent
        public async Task<bool> SendDataAsync(int streamId,
                                              byte[] data,
                                              bool endStream,
                                              CancellationToken cancellationToken = default)
        {
            bool sent = false;
            int offset = 0;

            if (!Streams.TryGetValue(streamId, out var s))
            {
                s = new Http2Stream(streamId,
                                    (int)Settings["SETTINGS_INITIAL_WINDOW_SIZE"]);
                Streams[streamId] = s;
            }

            while (offset < data.Length)
            {
                int allowed = Math.Min(s.WindowSize, _connectionWindowSize);
                if (allowed <= 0)
                {
                    // nothing available → give up for now
                    return sent;               // false if never wrote
                }

                int chunk = Math.Min(allowed,
                             Math.Min(PeerMaxFrameSize,
                                      data.Length - offset));

                byte flags = 0x00;
                bool lastChunk = (offset + chunk) == data.Length;
                if (lastChunk && endStream)
                    flags |= FLAG_END_STREAM;

                s.AddWindow(-chunk);
                _connectionWindowSize -= chunk;

                await SendFrame(FRAME_TYPE_DATA,
                                flags,
                                streamId,
                                new ReadOnlyMemory<byte>(data, offset, chunk),
                                cancellationToken);

                sent = true;
                offset += chunk;
            }
            return sent;
        }


        private readonly TaskCompletionSource<bool> _windowTcs =
                new TaskCompletionSource<bool>();

        private void OnWindowUpdate(int sid, int increment)
        {
            if (sid == 0)
                _connectionWindowSize += increment;
            else if (Streams.TryGetValue(sid, out var st))
                st.AddWindow(increment);

            _windowTcs.TrySetResult(true);            // wake any waiter
        }

        private async Task WaitForWindowUpdateAsync(int sid, CancellationToken ct)
        {
            using (ct.Register(() => _windowTcs.TrySetCanceled()))
            {
                await _windowTcs.Task.ConfigureAwait(false);
            }
            _windowTcs.TrySetResult(false);           // reset
        }


        // ---------------------------------------------------------------
        //  Convenience wrapper for RST_STREAM (errorCode = HTTP/2 code).
        // ---------------------------------------------------------------
        private Task SendRstStream(int streamId, int errorCode)
        {
            PodeHelpers.WriteErrorMessage($"DEBUG: About to send RST_STREAM, code {errorCode} (SID={streamId})", Context.Listener, PodeLoggingLevel.Verbose, Context);
            Console.WriteLine($"[DEBUG] SendRstStream: streamId={streamId}, errorCode=0x{errorCode:X8}");


            byte[] code = {
                (byte)((errorCode >> 24) & 0xFF),
                (byte)((errorCode >> 16) & 0xFF),
                (byte)((errorCode >> 8)  & 0xFF),
                (byte)( errorCode        & 0xFF)
            };

            const byte FRAME_TYPE_RST_STREAM = 0x3;
            const byte NO_FLAGS = 0x00;

            return SendFrame(FRAME_TYPE_RST_STREAM, NO_FLAGS, streamId, code);
        }
        private async Task CloseConnection(CancellationToken cancellationToken)
        {
            try
            {
                var networkStream = GetNetworkStream();
                if (networkStream != null)
                {
                    await networkStream.FlushAsync(cancellationToken);
                    networkStream.Close();      // closes underlying socket as well
                    networkStream.Dispose();
                }
            }
            catch (Exception ex)
            {
                // Log, but don't throw—you're shutting down anyway
                PodeHelpers.WriteErrorMessage($"DEBUG: Exception during connection close: {ex.Message}", Context.Listener, PodeLoggingLevel.Verbose, Context);
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

        private async Task ProcessSettingsFrame(Http2Frame frame,
                                         CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] ProcessSettingsFrame: Length={frame.Length}, Flags=0x{frame.Flags:X2}");

            // ACK → nothing to do
            if ((frame.Flags & FLAG_ACK) != 0)
            {
                Console.WriteLine("[DEBUG] Received SETTINGS ACK frame");
                if (frame.Length != 0)
                {
                    Console.WriteLine("[DEBUG] SETTINGS frame with ACK and payload, sending GOAWAY");
                    // RFC 7540 §6.5.3: SETTINGS frame with ACK and payload
                    await SendGoAwayAsync(0, Http2ErrorCode.FrameSizeError, "SETTINGS frame with ACK and payload", cancellationToken);
                    await CloseConnection(cancellationToken);
                    return;
                }
                // Normal ACK handling
                return;
            }
            // SETTINGS with stream ID != 0
            if (frame.StreamId != 0)
            {
                Console.WriteLine("[DEBUG] SETTINGS frame with non-zero stream ID, sending GOAWAY");
                // RFC 7540 §6.5.3: SETTINGS frame with non-zero stream
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "SETTINGS frame with non-zero stream ID", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }

            // SETTINGS frame with payload length not a multiple of 6
            if (frame.Length % 6 != 0)
            {
                Console.WriteLine("[DEBUG] SETTINGS frame with invalid length, sending GOAWAY");
                // RFC 7540 §6.5.3: SETTINGS frame with invalid length
                await SendGoAwayAsync(0, Http2ErrorCode.FrameSizeError, "SETTINGS frame with invalid length", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }
            for (int i = 0; i + 5 < frame.Payload.Length; i += 6)
            {
                int id = (frame.Payload[i] << 8) | frame.Payload[i + 1];
                int value = (frame.Payload[i + 2] << 24) |
                            (frame.Payload[i + 3] << 16) |
                            (frame.Payload[i + 4] << 8) |
                             frame.Payload[i + 5];

                string name = GetSettingName(id);
                if (name == null)
                {
                    Console.WriteLine($"[DEBUG] Unknown setting ID {id} = {value}");
                    continue;
                }

                Console.WriteLine($"[DEBUG] Setting: {name} = {value}");
                Settings[name] = value;

                switch (id)
                {
                    case 0x1:          // SETTINGS_HEADER_TABLE_SIZE
                        int oldSize = (int)Settings["SETTINGS_HEADER_TABLE_SIZE"];
                        Settings["SETTINGS_HEADER_TABLE_SIZE"] = value;
                        _hpackDecoder.SetMaxHeaderTableSize(value);
                        Console.WriteLine($"[DEBUG] HPACK dynamic table size {oldSize} → {value}");
                        break;


                    case 0x2: // SETTINGS_ENABLE_PUSH
                        if (value != 0 && value != 1)
                        {
                            await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "SETTINGS_ENABLE_PUSH must be 0 or 1", cancellationToken);
                            await CloseConnection(cancellationToken);
                            return;
                        }
                        break;
                    case 0x3:          // SETTINGS_MAX_CONCURRENT_STREAMS

                        break;
                    case 0x4:          // SETTINGS_INITIAL_WINDOW_SIZE

                        uint unsignedVal = (uint)value;

                        // RFC 7540 §6.9.2: must be ≤ 2^31-1
                        if (unsignedVal > 0x7FFFFFFF)
                        {
                            await SendGoAwayAsync(
                                    lastStreamId: 0,
                                    errorCode: Http2ErrorCode.FlowControlError,
                                    debugData: "SETTINGS_INITIAL_WINDOW_SIZE too large",
                                    cancellationToken);
                            return;     // caller closes socket
                        }

                        int old = (int)Settings["SETTINGS_INITIAL_WINDOW_SIZE"];
                        int diff = value - old;   // may be negative

                        Settings["SETTINGS_INITIAL_WINDOW_SIZE"] = value;

                        foreach (var stream in Streams.Values)
                        {
                            // Make every open stream’s window grow/shrink by diff
                            stream.AddWindow(diff);       // AddWindow already exists
                        }
                        _settingsTcs.TrySetResult(true);  // wakes any waiter
                        Console.WriteLine($"[DEBUG] Updated initial window {old} → {value} " +
                                            $"(applied diff {diff} to {Streams.Count} streams)");
                        break;

                     case 0x5:          // SETTINGS_MAX_FRAME_SIZE
                        if (value < 16384 || value > 16777215)
                        {
                          //  await SendRstStream(0, 0x1);   // PROTOCOL_ERROR on the connection
                            await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "SETTINGS_MAX_FRAME_SIZE out of range", cancellationToken);
                            await CloseConnection(cancellationToken);
                            return;
                        }
                        PeerMaxFrameSize = value;
                        Console.WriteLine($"[DEBUG] Peer max frame size → {PeerMaxFrameSize}");
                        break;

                    default:
                        {
                            Console.WriteLine($"[DEBUG] Unknown setting ID {id} = {value}");
                            break;
                        }
                }
            }

            // --- Send SETTINGS-ACK back to the peer -------------------------
            await SendSettingsAck();   // <-- make this awaitable if it isn’t
        }


        public async Task WaitForSettingsAsync(TimeSpan timeout, CancellationToken ct)
        {
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(timeout);
                try { await _settingsTcs.Task.WaitAsync(cts.Token); }
                catch (OperationCanceledException) { /* timeout – fine */ }
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

        private async Task ProcessPriorityFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] ProcessPriorityFrame: StreamId={frame.StreamId}, Length={frame.Length}, Flags=0x{frame.Flags:X2}");

             // RFC 7540 §6.3: StreamId == 0 is PROTOCOL_ERROR
            if (frame.StreamId == 0)
            {
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "PRIORITY frame on stream 0", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }
            // §6.6  Priority frame payload is always 5 octets.
            //       The first 4 octets are the stream dependency, and the last octet
            //       is the weight (0-255, representing 1-256).
            //       The stream dependency is a 31-bit integer, with the high bit reserved.
            //       If the high bit is set, the stream is exclusive.
            //       The stream ID 0 is reserved for connection-level frames.
            //       If the stream ID is 0, it means this is a connection-level priority
            //       and the dependency is ignored.
            //       The weight is a single byte, 0-255, representing 1-256.
            //       A weight of 0 is invalid and should be treated as 1.
            //       The stream ID 0 is reserved for connection-level frames.
            if (frame.Payload.Length != 5 ) return;

            uint dependency = (uint)((frame.Payload[0] << 24) |
                                     (frame.Payload[1] << 16) |
                                     (frame.Payload[2] << 8) |
                                      frame.Payload[3]);
            bool exclusive = (dependency & 0x8000_0000) != 0;
            dependency &= 0x7FFF_FFFF;

            byte weight = frame.Payload[4];           // 0–255 represents 1–256

            if (!Streams.ContainsKey(frame.StreamId))
                Streams[frame.StreamId] = new Http2Stream(frame.StreamId, (int)Settings["SETTINGS_INITIAL_WINDOW_SIZE"]);

            Streams[frame.StreamId].Dependency = dependency;
            Streams[frame.StreamId].Weight = (byte)(weight + 1); // store 1-256

            Console.WriteLine($"[DEBUG] PRIORITY: Stream={frame.StreamId} dep={dependency} excl={exclusive} weight={weight + 1}");
        }


        private async Task ProcessRstStreamFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            // 1. StreamId == 0 is a protocol error (RFC 7540 §6.4)
            if (frame.StreamId == 0)
            {
                Console.WriteLine($"[DEBUG] RST_STREAM frame on stream 0");
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "RST_STREAM frame on stream 0", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }

            // 2. Idle stream (never opened, ie not in Streams dictionary)
            if (!Streams.ContainsKey(frame.StreamId))
            {
                Console.WriteLine($"[DEBUG] RST_STREAM frame on idle stream {frame.StreamId}");
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "RST_STREAM frame on idle stream", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }

            // Normal handling for valid, open stream
            var errorCode = (frame.Payload[0] << 24) | (frame.Payload[1] << 16) |
                            (frame.Payload[2] << 8) | frame.Payload[3];

            Streams[frame.StreamId].Reset = true;
            Streams[frame.StreamId].ErrorCode = errorCode;
            Console.WriteLine($"[DEBUG] RST_STREAM: StreamId={frame.StreamId}, ErrorCode=0x{errorCode:X8}");
        }


        private async Task ProcessPingFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            Console.WriteLine($"[DEBUG] ProcessPingFrame: StreamId={frame.StreamId}, Length={frame.Length}, Flags=0x{frame.Flags:X2}");

            // RFC 7540 §6.7: PING must always use stream 0
            if (frame.StreamId != 0)
            {
                // Send GOAWAY with PROTOCOL_ERROR and close the connection
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "PING on non-zero stream", cancellationToken);
                await GetNetworkStream()?.FlushAsync(cancellationToken);
                GetNetworkStream()?.Dispose();
                // flag this connection for closure (implementation-specific)
                //_shouldClose = true;
                return;
            }
            // §6.7  Ping payload is always 8 octets.
            if (frame.Length != 8)
            {
                Console.WriteLine($"[DEBUG] Invalid PING frame length {frame.Length}, sending GOAWAY and closing connection");
                PodeHelpers.WriteErrorMessage($"DEBUG: Invalid PING frame length {frame.Length}, sending GOAWAY and closing connection", Context.Listener, PodeLoggingLevel.Verbose, Context);
                // Length error on the connection – send GOAWAY and close
                await SendGoAwayAsync(0, Http2ErrorCode.FrameSizeError, "Invalid PING frame length", cancellationToken);
                await CloseConnection(cancellationToken);
                return;
            }

            // Ignore peer’s ACKs
            if ((frame.Flags & FLAG_ACK) != 0)
            {
                Console.WriteLine($"[DEBUG] Ignoring PING ACK frame from peer");
                return;
            }

            // Send PING frame with ACK flag set, stream ID 0 (connection-level)
            // and the same payload as received
            // Note: Stream ID 0 is used for connection-level frames in HTTP/2
            //       and the PING frame is always sent on stream 0.
            //       The ACK flag indicates that this is a response to a PING request.
            //       The payload is the same as the received frame.
            //       This is a connection-level frame, so stream ID is always 0.
            Console.WriteLine($"[DEBUG] Sending PING ACK frame with payload: {BitConverter.ToString(frame.Payload).Replace("-", " ")}");

            await SendFrame(FRAME_TYPE_PING,
                            FLAG_ACK,
                            0,                   // always stream 0
                            frame.Payload);
            await GetNetworkStream().FlushAsync(cancellationToken);
        }

        private async void ProcessGoAwayFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            if (frame.StreamId != 0)
            {
                // MUST treat as connection error of type PROTOCOL_ERROR
                await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "GOAWAY with non-zero stream ID");
                await CloseConnection(cancellationToken); // or use current token if available
                return;
            }

            // Optionally: handle normal GOAWAY logic here
            await CloseConnection(cancellationToken);
        }

        internal async Task SendGoAwayAsync(uint lastStreamId, Http2ErrorCode errorCode, string debugData = null, CancellationToken cancellationToken = default(CancellationToken))
        {
            // ---- build core 8-byte payload (big-endian) ------------------
            int debugLen = string.IsNullOrEmpty(debugData) ? 0
                                                           : System.Text.Encoding.ASCII.GetByteCount(debugData);
            byte[] payload = new byte[8 + debugLen];

            // 31-bit Last-Stream-ID (high bit must be 0)
            payload[0] = (byte)((lastStreamId >> 24) & 0x7F);
            payload[1] = (byte)((lastStreamId >> 16) & 0xFF);
            payload[2] = (byte)((lastStreamId >> 8) & 0xFF);
            payload[3] = (byte)(lastStreamId & 0xFF);

            // 32-bit Error Code
            uint ec = (uint)errorCode;
            payload[4] = (byte)((ec >> 24) & 0xFF);
            payload[5] = (byte)((ec >> 16) & 0xFF);
            payload[6] = (byte)((ec >> 8) & 0xFF);
            payload[7] = (byte)(ec & 0xFF);

            // optional debug string (ASCII as per RFC 7540 §7)
            if (debugLen > 0)
            {
                System.Text.Encoding.ASCII.GetBytes(debugData, 0, debugData.Length, payload, 8);
            }

            // ---- transmit ------------------------------------------------
            await SendFrame(FRAME_TYPE_GOAWAY, 0x00, 0, payload, cancellationToken)
                .ConfigureAwait(false);

            var ns = GetNetworkStream();
            if (ns != null)
            {
                await ns.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }



        //-----------------------------------------------------------------
        //  WINDOW_UPDATE – adjust flow-control windows (RFC 7540 §6.9)
        //-----------------------------------------------------------------
        private async Task ProcessWindowUpdateFrame(Http2Frame frame, CancellationToken cancellationToken)
        {
            PodeHelpers.WriteErrorMessage($"DEBUG: Entered ProcessWindowUpdateFrame (SID={frame.StreamId}, Length={frame.Length})", Context.Listener, PodeLoggingLevel.Verbose, Context);
            Console.WriteLine($"[DEBUG] ProcessWindowUpdateFrame: StreamId={frame.StreamId}, Length={frame.Length}");
            // 1. Bad payload length = connection error
            if (frame.Length != 4)
            {
                await SendGoAwayAsync(0, Http2ErrorCode.FrameSizeError, "Invalid WINDOW_UPDATE frame length", cancellationToken);
                Console.WriteLine("[DEBUG] Invalid WINDOW_UPDATE frame length, sending GOAWAY and closing connection");
                await CloseConnection(cancellationToken); // implement this to close socket/stream
                return;
            }

            int increment = ((frame.Payload[0] << 24) |
                             (frame.Payload[1] << 16) |
                             (frame.Payload[2] << 8) |
                              frame.Payload[3]) & 0x7FFF_FFFF;

            // 2. Zero increment = PROTOCOL_ERROR
            if (increment == 0)
            {
                if (frame.StreamId == 0)
                {
                    await SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "Zero WINDOW_UPDATE frame increment", cancellationToken);
                    Console.WriteLine("[DEBUG] Zero WINDOW_UPDATE increment on connection, sending GOAWAY and closing connection");
                    await CloseConnection(cancellationToken);   // implement this to close socket/stream
                }
                else
                {
                    await SendRstStream(frame.StreamId, (int)Http2ErrorCode.ProtocolError);
                }
                return;
            }

            // 3. Window overflow = FLOW_CONTROL_ERROR
            if (frame.StreamId == 0)
            {
                long newSize = (long)_connectionWindowSize + increment;
                if (newSize > int.MaxValue)
                {
                    await SendGoAwayAsync(0, Http2ErrorCode.FlowControlError, "Connection flow control window overflow", cancellationToken);
                    Console.WriteLine("[DEBUG] Connection flow control window overflow, sending GOAWAY and closing connection");
                    await CloseConnection(cancellationToken); // implement this to close socket/stream
                    return;
                }
                _connectionWindowSize = (int)newSize;
                return;
            }
            else
            {
                var stream = GetOrCreateStream(frame.StreamId);
                long newStreamSize = (long)stream.WindowSize + increment;
                if (newStreamSize > int.MaxValue)
                {
                    await SendRstStream(frame.StreamId, (int)Http2ErrorCode.FlowControlError);
                    Console.WriteLine("[DEBUG] Stream flow control window overflow, sending RST_STREAM");
                    return;
                }
                stream.AddWindow(increment);
                return;
            }
        }

        private Http2Stream GetOrCreateStream(int streamId)
        {
            if (!Streams.TryGetValue(streamId, out var stream))
            {
                // Use your constructor with window size!
                int initialWindow = (int)Settings["SETTINGS_INITIAL_WINDOW_SIZE"];
                stream = new Http2Stream(streamId, initialWindow);
                Streams[streamId] = stream;
            }
            return stream;
        }



        // ---------------------------------------------------------------------
        //  Handles a CONTINUATION frame that follows HEADERS/CONTINUATION.
        // ---------------------------------------------------------------------
        private async Task ProcessContinuationFrame(Http2Frame frame,
                                            CancellationToken cancellationToken)
        {
            if (!Streams.ContainsKey(StreamId))
                return;                 // protocol error; nothing to continue

            var stream = Streams[StreamId];
            var headerListener = new ListHeaderListener();
            try
            {
                using (var ms = new MemoryStream(frame.Payload, 0, frame.Payload.Length))
                using (var br = new BinaryReader(ms, System.Text.Encoding.UTF8, leaveOpen: true))
                {
                    _hpackDecoder.Decode(br, headerListener);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] HPACK decode failed in CONTINUATION: {ex.Message}");
                await SendRstStream(frame.StreamId, 0x1);   // PROTOCOL_ERROR
                return;
            }
            foreach (var (name, value) in headerListener.Headers)
            {
                stream.Headers[name] = value;
            }

            if ((frame.Flags & FLAG_END_HEADERS) != 0)
            {
                _hpackDecoder.EndHeaderBlock();
                await FinalizeHeaders(stream, cancellationToken);
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

                // Validate and sanitize header values
                if (string.IsNullOrEmpty(value))
                    value = "";
                else
                {
                    value = PodeHttp2Request.SanitizeHeaderValue(value);

                    // Check for obvious corruption and provide fallbacks
                    if (PodeHttp2Request.ContainsCorruptedData(value))
                    {
                        Console.WriteLine($"[WARNING] Corrupted header value detected for '{key}': '{value}'");

                        // Provide sensible defaults for critical headers
                        if (key == ":authority" || key.ToLower() == "host")
                        {
                            value = "localhost"; // Default host
                        }
                        else if (key == ":method")
                        {
                            value = "GET"; // Default method
                        }
                        else if (key == ":path")
                        {
                            value = "/"; // Default path
                        }
                        else if (key == ":scheme")
                        {
                            value = "https"; // Default scheme
                        }
                        else
                        {
                            // For other headers, use empty string or skip
                            value = "";
                        }
                    }
                }

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
                    // Only add non-empty headers
                    if (!string.IsNullOrEmpty(value))
                    {
                        Headers[key] = value;
                    }

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

            Console.WriteLine($"[DEBUG] FinalizeHeaders complete: _isHeadersComplete={_isHeadersComplete}, ContentLength={ContentLength}, EndOfStream={EndOfStream}, AwaitingBody={AwaitingBody}");
            Console.WriteLine($"[DEBUG] FinalizeHeaders - HttpMethod='{HttpMethod}', Host='{Host}', Url='{Url}'");

            if (Streams.TryGetValue(StreamId, out var s))
            {
                Console.WriteLine($"[DEBUG] Final PRIORITY: Stream={s.StreamId} dep={s.Dependency} weight={s.Weight}");
            }

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

                // _hpackDecoder is readonly and cannot be set to null here
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
                PodeHttp2Request.AddSetting(settingsData, 1, 4096);  // SETTINGS_HEADER_TABLE_SIZE
                PodeHttp2Request.AddSetting(settingsData, 2, 0);     // SETTINGS_ENABLE_PUSH (disabled)
                PodeHttp2Request.AddSetting(settingsData, 3, 100);   // SETTINGS_MAX_CONCURRENT_STREAMS
                PodeHttp2Request.AddSetting(settingsData, 4, 65535); // SETTINGS_INITIAL_WINDOW_SIZE
                PodeHttp2Request.AddSetting(settingsData, 5, 16384); // SETTINGS_MAX_FRAME_SIZE
                PodeHttp2Request.AddSetting(settingsData, 6, 8192);  // SETTINGS_MAX_HEADER_LIST_SIZE

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

        private static void AddSetting(List<byte> settingsData, int settingId, int value)
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
        public async Task FlushAsync(CancellationToken cancellationToken)
        {
            await GetNetworkStream().FlushAsync(cancellationToken);
        }


        // Use the GetNetworkStream method to ensure we have the correct stream
        private Stream GetNetworkStream()
        {
            try
            {
                // Use the existing InputStream if available, or create a NetworkStream
                if (InputStream != null)
                {
                    return InputStream;
                }
                Console.WriteLine("[DEBUG] No InputStream available, trying to get NetworkStream from socket");
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

        private static bool ContainsCorruptedData(string text)
        {
            // Check for obvious signs of corruption
            if (string.IsNullOrEmpty(text))
                return false;

            // Count non-printable characters (excluding common control chars like \r, \n, \t)
            int nonPrintableCount = 0;
            foreach (char c in text)
            {
                if (c < 32 && c != '\r' && c != '\n' && c != '\t')
                    nonPrintableCount++;
                else if (c > 126 && c < 160) // Common non-printable range
                    nonPrintableCount++;
            }

            // If more than 20% of characters are non-printable, likely corrupted
            return nonPrintableCount > (text.Length * 0.2);
        }

        private static string SanitizeHeaderValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            var result = new System.Text.StringBuilder();
            foreach (char c in value)
            {
                // Only include printable ASCII and common control characters
                if ((c >= 32 && c <= 126) || c == '\t' || c == '\r' || c == '\n')
                {
                    result.Append(c);
                }
                else
                {
                    result.Append('?'); // Replace invalid characters with ?
                }
            }
            return result.ToString();
        }


        public override async Task<bool> Receive(CancellationToken cancellationToken)
        {
            Console.WriteLine("[DEBUG] PodeHttp2Request.Receive() called");

            // Check if we have stored preface data from the HTTP/1.1 parser
            if (Context.Data.ContainsKey("Http2PrefaceData"))
            {
                Console.WriteLine("[DEBUG] Found stored preface data, processing it first");
                var prefaceData = (byte[])Context.Data["Http2PrefaceData"];
                Console.WriteLine($"[DEBUG] Processing {prefaceData.Length} bytes of stored preface data");

                // Process the stored preface data
                try
                {
                    if (ValidateInput(prefaceData))
                    {
                        Console.WriteLine("[DEBUG] Stored preface data validation passed, calling Parse");
                        if (await Parse(prefaceData, cancellationToken).ConfigureAwait(false))
                        {
                            Console.WriteLine("[DEBUG] Stored preface data parsed successfully");
                            // Remove the stored data so we don't use it again
                            Context.Data.Remove("Http2PrefaceData");

                            // If parsing was successful and we have a complete request, return false (don't close)
                            if (IsProcessable)
                            {
                                Console.WriteLine("[DEBUG] Request is processable, returning false (don't close connection)");
                                return false;
                            }
                        }
                        else
                        {
                            Console.WriteLine("[DEBUG] Stored preface data parsing returned false, continuing with normal receive");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[DEBUG] Stored preface data validation failed, continuing with normal receive");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DEBUG] Error processing stored preface data: {ex.Message}");
                    // Continue with normal receive if there's an error
                }
            }

            // Continue with normal receive processing
            Console.WriteLine("[DEBUG] Continuing with base Receive method");
            return await base.Receive(cancellationToken).ConfigureAwait(false);
        }


    }


}
#endif