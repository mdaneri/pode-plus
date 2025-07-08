using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Web;
using System.Linq;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Pode
{
    public class PodeHttpRequest : PodeRequest
    {
        public string HttpMethod { get; protected set; }
        public NameValueCollection QueryString { get; protected set; }
        public string Protocol { get; protected set; }
        public string ProtocolVersion { get; protected set; }
        public string ContentType { get; protected set; }
        public int ContentLength { get; protected set; }
        public Encoding ContentEncoding { get; protected set; }
        public string TransferEncoding { get; protected set; }
        public string UserAgent { get; protected set; }
        public string UrlReferrer { get; protected set; }
        public Uri Url { get; protected set; }
        public Hashtable Headers { get; protected set; }
        public byte[] RawBody { get; protected set; }
        public string Host { get; protected set; }
        public bool AwaitingBody { get; protected set; }
        public PodeForm Form { get; protected set; }

        private bool IsRequestLineValid;
        private MemoryStream BodyStream;
#if !NETSTANDARD2_0
        private bool _hasCheckedForHttp2Upgrade = false;
#endif
        public string SseClientId { get; private set; }
        public string SseClientName { get; private set; }
        public string SseClientGroup { get; private set; }
        public bool HasSseClientId
        {
            get => !string.IsNullOrEmpty(SseClientId);
        }

        protected string _body = string.Empty;
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
            get => !CloseImmediately && !AwaitingBody;
        }

        public PodeHttpRequest(Socket socket, PodeSocket podeSocket, PodeContext context)
            : base(socket, podeSocket, context)
        {
            Protocol = "HTTP/1.1";
            Type = PodeProtocolType.Http;
        }


        /// <summary>
        /// Copy-constructor – creates a deep(ish) clone of an existing request.
        /// Socket, PodeSocket and Context are *shared* so the new object
        /// still points at the same connection; everything else is copied.
        /// </summary>
        public PodeHttpRequest(PodeHttpRequest other)
            : base(other)
        {
            if (other == null) throw new ArgumentNullException(nameof(other));

            // simple value types / strings
            HttpMethod = other.HttpMethod;
            Protocol = other.Protocol;
            ProtocolVersion = other.ProtocolVersion;
            ContentType = other.ContentType;
            ContentLength = other.ContentLength;
            TransferEncoding = other.TransferEncoding;
            UserAgent = other.UserAgent;
            UrlReferrer = other.UrlReferrer;
            Host = other.Host;
            AwaitingBody = other.AwaitingBody;

            // reference types that need a *new* instance
            ContentEncoding = other.ContentEncoding;
            Url = other.Url != null ? new Uri(other.Url.ToString()) : null;
            Headers = other.Headers != null ? (Hashtable)other.Headers.Clone() : new Hashtable(StringComparer.InvariantCultureIgnoreCase);
            QueryString = other.QueryString != null ? new NameValueCollection(other.QueryString) : null;
            RawBody = other.RawBody != null ? (byte[])other.RawBody.Clone() : null;

            // optional items – clone or share as makes sense for your code-base
            Form = other.Form; // shallow; replace with a deep copy if PodeForm is mutable

            // SSE metadata
            SseClientId = other.SseClientId;
            SseClientName = other.SseClientName;
            SseClientGroup = other.SseClientGroup;

            // keep-alive / TLS flags, etc.
            IsKeepAlive = other.IsKeepAlive;
            SslUpgraded = other.SslUpgraded;
        }

        protected override bool ValidateInput(byte[] bytes)
        {
            // we need more bytes!
            if (bytes.Length == 0)
            {
                return false;
            }

            // wait until we have the rest of the payload
            if (AwaitingBody)
            {
                return bytes.Length >= (ContentLength - BodyStream.Length);
            }

            var previousIndex = -1;
            var index = Array.IndexOf(bytes, PodeHelpers.NEW_LINE_BYTE);

            // do we have a request line yet?
            if (index == -1)
            {
                return false;
            }

            // is the request line valid?
            if (!IsRequestLineValid)
            {
                var reqLine = Encoding.GetString(bytes, 0, index).Trim();
                var reqMeta = reqLine.Split(PodeHelpers.SPACE_ARRAY, StringSplitOptions.RemoveEmptyEntries);

                if (reqMeta.Length != 3)
                {
                    throw new PodeRequestException($"Invalid request line: {reqLine} [{reqMeta.Length}]");
                }

                IsRequestLineValid = true;
            }

            // check if we have all the headers
            while (true)
            {
                previousIndex = index;
                index = Array.IndexOf(bytes, PodeHelpers.NEW_LINE_BYTE, index + 1);

                // If the difference between indexes indicates the end of headers, exit the loop
                if (index == previousIndex + 1 ||
                    (index > previousIndex + 1 && bytes[previousIndex + 1] == PodeHelpers.CARRIAGE_RETURN_BYTE))
                {
                    break;
                }

                // Return false if LF not found and end of array is reached
                if (index == -1 || index >= bytes.Length - 1)
                {
                    return false;
                }
            }

            // we're valid!
            IsRequestLineValid = false;
            return true;
        }

        protected override async Task<bool> Parse(byte[] bytes, CancellationToken cancellationToken)
        {
            // if there are no bytes, return (0 bytes read means we can close the socket)
            if (bytes.Length == 0)
            {
                HttpMethod = string.Empty;
                return true;
            }

#if !NETSTANDARD2_0
            // Check for HTTP/2 upgrade after SSL handshake
            if (IsSsl && !_hasCheckedForHttp2Upgrade)
            {
                _hasCheckedForHttp2Upgrade = true;
                Console.WriteLine("[DEBUG] Checking for post-SSL HTTP/2 upgrade in HTTP/1.1 parser");

                // Check if ALPN negotiated HTTP/2
                bool alpnNegotiatedHttp2 = Context.Data.ContainsKey("AlpnNegotiatedHttp2") && (bool)Context.Data["AlpnNegotiatedHttp2"];

                // Check if this looks like HTTP/2 preface
                var isHttp2Preface = bytes.Length >= 3 &&
                    System.Text.Encoding.ASCII.GetString(bytes, 0, 3) == "PRI";
                Console.WriteLine($"[DEBUG] HTTP/2 preface check: {System.Text.Encoding.ASCII.GetString(bytes, 0, 10)}");
                Console.WriteLine($"[DEBUG] ALPN negotiated HTTP/2: {alpnNegotiatedHttp2}, Has HTTP/2 preface: {isHttp2Preface}");

                if (alpnNegotiatedHttp2 && isHttp2Preface)
                {
                    Console.WriteLine("[DEBUG] ✅ Delegating to HTTP/2 parser after detecting ALPN + preface");
                    PodeHelpers.WriteErrorMessage("ALPN negotiated HTTP/2 and HTTP/2 preface detected, switching to HTTP/2 processing", Context.Listener, PodeLoggingLevel.Debug, Context);

                    // Store the preface data so the HTTP/2 parser can use it
                    Context.Data["Http2PrefaceData"] = bytes;
                    Console.WriteLine($"[DEBUG] Stored {bytes.Length} bytes of preface data for HTTP/2 parser");

                    // This is a more elegant approach: throw an exception that the context can catch
                    // and use to switch to HTTP/2 parser. This avoids complex state copying.
                    throw new PodeRequestException("HTTP_2_UPGRADE_REQUIRED", 422);
                }
                else if (!alpnNegotiatedHttp2 && isHttp2Preface)
                {
                    Console.WriteLine("[DEBUG] ❌ HTTP/2 preface without ALPN negotiation - this is an error");
                    throw new PodeRequestException("HTTP/2 connection preface detected but ALPN did not negotiate HTTP/2. This indicates a client or protocol error.", 400);
                }
            }
#endif

            // new line char
            var newline = Array.IndexOf(bytes, PodeHelpers.CARRIAGE_RETURN_BYTE) == -1
                ? PodeHelpers.NEW_LINE_UNIX
                : PodeHelpers.NEW_LINE;

            // parse the headers, unless we're waiting for the body
            var bodyIndex = 0;
            if (!AwaitingBody)
            {
                var content = Encoding.GetString(bytes, 0, bytes.Length);
                var reqLines = content.Split(new string[] { newline }, StringSplitOptions.None);
                content = string.Empty;

                bodyIndex = ParseHeaders(reqLines);
                bodyIndex = reqLines.Take(bodyIndex).Sum(x => x.Length) + (bodyIndex * newline.Length);
                reqLines = default;
            }

            // parse the body
            await ParseBody(bytes, newline, bodyIndex, cancellationToken).ConfigureAwait(false);
            AwaitingBody = ContentLength > 0 && BodyStream.Length < ContentLength && Error == default(PodeRequestException);

            if (!AwaitingBody)
            {
                RawBody = BodyStream.ToArray();

                if (BodyStream != default(MemoryStream))
                {
                    BodyStream.Dispose();
                    BodyStream = default;
                }
            }

            return !AwaitingBody;
        }

        private int ParseHeaders(string[] reqLines)
        {
            // reset raw body
            RawBody = default;
            _body = string.Empty;

            // first line is method/url
            var reqMeta = reqLines[0].Trim().Split(' ');
            if (reqMeta.Length != 3)
            {
                throw new PodeRequestException($"Invalid request line: {reqLines[0]} [{reqMeta.Length}]");
            }

            // http method
            HttpMethod = reqMeta[0].Trim().ToUpper();

            // Special handling for HTTP/2 connection preface that ended up in HTTP/1.1 parser
            if (HttpMethod == "PRI")
            {
#if NETCOREAPP2_1_OR_GREATER
                // Check if ALPN actually negotiated HTTP/2
                if (Context.Data.ContainsKey("AlpnNegotiatedHttp2") && (bool)Context.Data["AlpnNegotiatedHttp2"])
                {
                    // ALPN negotiated HTTP/2, but we're in the HTTP/1.1 parser
                    // This is the timing issue we're trying to fix
                    throw new PodeRequestException("HTTP/2 connection detected after ALPN negotiation. Request should be handled by HTTP/2 parser.", 422);
                }
                else
                {
                    // No HTTP/2 ALPN negotiation, this is an error
                    throw new PodeRequestException("HTTP/2 connection preface detected in HTTP/1.1 parser. This indicates a protocol detection issue.", 400);
                }
#else
                throw new PodeRequestException("HTTP/2 is not supported in this version. Please use HTTP/1.1.", 400);
#endif
            }

            if (!PodeHelpers.HTTP_METHODS.Contains(HttpMethod))
            {
                throw new PodeRequestException($"Invalid request HTTP method: {HttpMethod}", 405);
            }

            // query string
            var reqQuery = reqMeta[1].Trim();
            var qmIndex = reqQuery.IndexOf("?");

            QueryString = qmIndex > 0
                ? HttpUtility.ParseQueryString(reqQuery.Substring(qmIndex + 1))
                : default;

            // http protocol version
            Protocol = (reqMeta[2] ?? "HTTP/1.1").Trim();
            if (!Protocol.StartsWith("HTTP/"))
            {
                throw new PodeRequestException($"Invalid request version: {Protocol}", 505);
            }

            ProtocolVersion = Protocol.Split('/')[1];

            // headers
            Headers = new Hashtable(StringComparer.InvariantCultureIgnoreCase);
            var bodyIndex = 0;
            var h_index = 0;
            var h_line = string.Empty;
            var h_name = string.Empty;
            var h_value = string.Empty;

            for (var i = 1; i <= reqLines.Length - 1; i++)
            {
                h_line = reqLines[i].Trim();
                if (string.IsNullOrWhiteSpace(h_line))
                {
                    bodyIndex = i + 1;
                    break;
                }

                h_index = h_line.IndexOf(":");
                if (h_index > 0)
                {
                    h_name = h_line.Substring(0, h_index).Trim();
                    h_value = h_line.Substring(h_index + 1).Trim();
                    Headers.Add(h_name, h_value);
                }
            }

            // build required URI details
            var _proto = IsSsl ? "https" : "http";
            Host = Headers["Host"]?.ToString();

            // check the host header
            if (string.IsNullOrWhiteSpace(Host) || !Context.PodeSocket.CheckHostname(Host))
            {
                throw new PodeRequestException($"Invalid Host header: {Host}");
            }

            // build the URL
            Url = new Uri($"{_proto}://{Host}{reqQuery}");

            // get the content length
            ContentLength = 0;
            if (int.TryParse(Headers["Content-Length"]?.ToString(), out int _contentLength))
            {
                ContentLength = _contentLength;
            }

            // set the transfer encoding
            TransferEncoding = Headers["Transfer-Encoding"]?.ToString();

            // set other default headers
            UrlReferrer = Headers["Referer"]?.ToString();
            UserAgent = Headers["User-Agent"]?.ToString();
            ContentType = Headers["Content-Type"]?.ToString();

            // set content encoding
            ContentEncoding = System.Text.Encoding.UTF8;
            if (!string.IsNullOrWhiteSpace(ContentType))
            {
                var atoms = ContentType.Split(';');
                foreach (var atom in atoms)
                {
                    if (atom.Trim().StartsWith("charset", StringComparison.InvariantCultureIgnoreCase))
                    {
                        ContentEncoding = System.Text.Encoding.GetEncoding(atom.Split('=')[1].Trim());
                        break;
                    }
                }
            }

            // is web-socket?
            if (Headers.ContainsKey("Sec-WebSocket-Key"))
            {
                Type = PodeProtocolType.Ws;
            }

            // do we have an SSE ClientId?
            SseClientId = Headers["X-Pode-Sse-Client-Id"]?.ToString();
            if (HasSseClientId)
            {
                SseClientName = Headers["X-Pode-Sse-Name"]?.ToString();
                SseClientGroup = Headers["X-Pode-Sse-Group"]?.ToString();
            }

            // keep-alive?
            IsKeepAlive = IsWebSocket ||
                (Headers.ContainsKey("Connection")
                    && Headers["Connection"]?.ToString().Equals("keep-alive", StringComparison.InvariantCultureIgnoreCase) == true);

            // return index where body starts in req
            return bodyIndex;
        }

        private async Task ParseBody(byte[] bytes, string newline, int start, CancellationToken cancellationToken)
        {
            // set the body stream
            if (BodyStream == default(MemoryStream))
            {
                BodyStream = new MemoryStream();
            }

            // are we chunked?
            var isChunked = !string.IsNullOrWhiteSpace(TransferEncoding) && TransferEncoding.Contains("chunked");

            // if chunked, and we have a content-length, fail
            if (isChunked && ContentLength > 0)
            {
                throw new PodeRequestException($"Cannot supply a Content-Length and a chunked Transfer-Encoding", 409);
            }

            // parse for chunked
            if (isChunked)
            {
                var c_length = -1;
                var c_index = 0;
                var c_hexBytes = default(IEnumerable<byte>);
                var c_rawBytes = new List<byte>();
                var c_hex = string.Empty;

                while (c_length != 0)
                {
                    // get index of newline char, read start>index bytes as HEX for length
                    c_index = Array.IndexOf(bytes, (byte)newline[0], start);
                    c_hexBytes = PodeHelpers.Slice(bytes, start, c_index - start);
                    c_hex = Encoding.GetString(c_hexBytes.ToArray());

                    // if no length, continue
                    c_length = Convert.ToInt32(c_hex, 16);
                    if (c_length == 0)
                    {
                        continue;
                    }

                    // read those X hex bytes from (newline index + newline length)
                    start = c_index + newline.Length;
                    c_rawBytes.AddRange(PodeHelpers.Slice(bytes, start, c_length));

                    // skip bytes for ending newline, and set new start
                    start = (start + c_length - 1) + newline.Length + 1;
                }

                await PodeHelpers.WriteTo(BodyStream, c_rawBytes.ToArray(), 0, c_rawBytes.Count, cancellationToken).ConfigureAwait(false);
            }

            // else use content length
            else if (ContentLength > 0)
            {
                await PodeHelpers.WriteTo(BodyStream, bytes, start, ContentLength, cancellationToken).ConfigureAwait(false);
            }

            // else just read all
            else
            {
                await PodeHelpers.WriteTo(BodyStream, bytes, start, 0, cancellationToken).ConfigureAwait(false);
            }

            // check body size
            if (BodyStream.Length > Context.Listener.RequestBodySize)
            {
                AwaitingBody = false;
                throw new PodeRequestException("Payload too large", 413);
            }
        }

        public void ParseFormData()
        {
            Form = PodeForm.Parse(RawBody, ContentType, ContentEncoding);
        }

        public bool IsHttpMethodValid()
        {
            if (string.IsNullOrWhiteSpace(HttpMethod) || !PodeHelpers.HTTP_METHODS.Contains(HttpMethod))
            {
                return false;
            }

            if (IsWebSocket && HttpMethod != "GET")
            {
                return false;
            }

            return true;
        }

        public override void PartialDispose()
        {
            if (BodyStream != default(MemoryStream))
            {
                BodyStream.Dispose();
                BodyStream = default;
            }

            base.PartialDispose();
        }

        /// <summary>
        /// Dispose managed and unmanaged resources.
        /// </summary>
        /// <param name="disposing">Indicates whether the method is called explicitly or by garbage collection.</param>
        protected override void Dispose(bool disposing)
        {
            if (IsDisposed) return;

            if (disposing)
            {
                // Custom cleanup logic for PodeHttpRequest
                RawBody = default;
                _body = string.Empty;

                if (BodyStream != default(MemoryStream))
                {
                    BodyStream.Dispose();
                    BodyStream = default;
                }

                if (Form != default(PodeForm))
                {
                    Form.Dispose();
                    Form = default;
                }
            }

            // Call the base Dispose to clean up shared resources
            base.Dispose(disposing);
        }
    }
}