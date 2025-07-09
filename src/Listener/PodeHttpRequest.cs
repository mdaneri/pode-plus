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

        protected MemoryStream _bodyStream;
#if NETCOREAPP2_1_OR_GREATER
        protected bool _hasCheckedForHttp2Upgrade = false;
#endif
        public string SseClientId { get; protected set; }
        public string SseClientName { get; protected set; }
        public string SseClientGroup { get; protected set; }
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
            if (_bodyStream != default(MemoryStream))
            {
                _bodyStream.Dispose();
                _bodyStream = default;
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

                if (_bodyStream != default(MemoryStream))
                {
                    _bodyStream.Dispose();
                    _bodyStream = default;
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