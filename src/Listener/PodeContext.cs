using System;
using System.Collections;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Pode
{
    /// <summary>
    /// Represents the context for a Pode request, including state management, request handling, and response processing.
    /// </summary>
    public class PodeContext : PodeProtocol, IDisposable
    {
        // Unique identifier for the context.
        public string ID { get; private set; }

        // Represents the incoming request.
        public PodeRequest Request { get; private set; }

        // Represents the outgoing response.
        public PodeResponse Response { get; private set; }

        // Listener associated with the context.
        public PodeListener Listener { get; private set; }

        // The socket for the current connection.
        public Socket Socket { get; private set; }

        // The Pode socket associated with the context.
        public PodeSocket PodeSocket { get; private set; }

        // Timestamp when the context was created.
        public DateTime Timestamp { get; private set; }

        // Data storage for request-specific metadata.
        public Hashtable Data { get; private set; }

        // The name of the endpoint associated with the socket.
        public string EndpointName => PodeSocket.Name;

        // Object used for thread-safety.
        private object _lockable = new object();

        // State of the context.
        private PodeContextState _state;
        public PodeContextState State
        {
            get => _state;
            private set
            {
                // Only allow changing from Timeout if transitioning to Closed or Error.
                if (_state != PodeContextState.Timeout || value == PodeContextState.Closed || value == PodeContextState.Error)
                {
                    _state = value;
                }
            }
        }

        // Determines if the context should be closed immediately.
        public bool CloseImmediately => State == PodeContextState.Error
                || State == PodeContextState.Closing
                || State == PodeContextState.Timeout
                || Request.CloseImmediately;

        // Determines if the context is associated with a WebSocket.
        public new bool IsWebSocket => base.IsWebSocket || (IsUnknown && PodeSocket.IsWebSocket);
        public bool IsWebSocketUpgraded => IsWebSocket && Request is PodeSignalRequest;

        // Determines if the context is associated with SMTP.
        public new bool IsSmtp => base.IsSmtp || (IsUnknown && PodeSocket.IsSmtp);

        // Determines if the context is associated with HTTP (including HTTP/2).
        public new bool IsHttp => base.IsHttp || (IsUnknown && PodeSocket.IsHttp)
#if !NETSTANDARD2_0
                                || IsHttp2
#endif
                                ;

#if !NETSTANDARD2_0
        // Determines if the context is associated with HTTP/2.
        public bool IsHttp2 => Request is PodeHttp2Request;
#endif

        // Strongly typed request properties for different protocols.
        public PodeSmtpRequest SmtpRequest => (PodeSmtpRequest)Request;
        public PodeHttpRequest HttpRequest => Request as PodeHttpRequest ??
            throw new InvalidOperationException("Request is not HTTP/1.x");
#if !NETSTANDARD2_0
        public PodeHttp2Request Http2Request => Request as PodeHttp2Request ??
            throw new InvalidOperationException("Request is not HTTP/2.0");
#endif
        public PodeSignalRequest SignalRequest => (PodeSignalRequest)Request;

        // Determines if the connection should be kept alive.
        public bool IsKeepAlive => (Request.IsKeepAlive && Response.SseScope != PodeSseScope.Local) || Response.SseScope == PodeSseScope.Global;

        // Flags for different context states.
        public bool IsErrored => State == PodeContextState.Error;
        public bool IsTimeout => State == PodeContextState.Timeout;
        public bool IsClosed => State == PodeContextState.Closed;
        public bool IsOpened => State == PodeContextState.Open;

        // Token and timer for managing request timeouts.
        public CancellationTokenSource ContextTimeoutToken { get; private set; }
        private Timer TimeoutTimer;

        /// <summary>
        /// Initializes a new PodeContext with the given socket, PodeSocket, and listener.
        /// </summary>
        /// <param name="socket">The socket used for the current connection.</param>
        /// <param name="podeSocket">The PodeSocket managing this context.</param>
        /// <param name="listener">The PodeListener associated with this context.</param>
        public PodeContext(Socket socket, PodeSocket podeSocket, PodeListener listener)
        {
            ID = PodeHelpers.NewGuid();
            Socket = socket;
            PodeSocket = podeSocket;
            Listener = listener;
            Timestamp = DateTime.UtcNow;
            Data = new Hashtable(StringComparer.InvariantCultureIgnoreCase);

            Type = PodeProtocolType.Unknown;
            State = PodeContextState.New;
        }

        /// <summary>
        /// Initializes the request and response for the context.
        /// </summary>
        /// <returns>A Task representing the async operation.</returns>
        public async Task Initialise()
        {
            await NewRequest().ConfigureAwait(false);
            NewResponse();
        }

        /// <summary>
        /// Callback for handling request timeouts.
        /// </summary>
        /// <param name="state">An object containing state information for the callback.</param>
        private void TimeoutCallback(object state)
        {
            try
            {
                PodeHelpers.WriteErrorMessage("TimeoutCallback triggered", Listener, PodeLoggingLevel.Debug, this);

                if (Response.SseEnabled || Request.IsWebSocket)
                {
                    PodeHelpers.WriteErrorMessage("Timeout ignored due to SSE/WebSocket", Listener, PodeLoggingLevel.Debug, this);
                    return;
                }

                PodeHelpers.WriteErrorMessage($"Request timeout reached: {Listener.RequestTimeout} seconds", Listener, PodeLoggingLevel.Warning, this);

                ContextTimeoutToken.Cancel();
                State = PodeContextState.Timeout;

                Response.StatusCode = 408;
                Request.Error = new PodeRequestException($"Request timeout [ContextId: {this.ID}]", 408);

                Dispose();
                PodeHelpers.WriteErrorMessage($"Request timeout reached: Dispose", Listener, PodeLoggingLevel.Debug, this);
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteErrorMessage($"Exception in TimeoutCallback: {ex}", Listener, PodeLoggingLevel.Error);
            }
        }

        /// <summary>
        /// Creates a new response object for the current context.
        /// </summary>
        private void NewResponse()
        {
#if !NETSTANDARD2_0
            // Create HTTP/2 response if the request is HTTP/2, otherwise use standard response
            if (Request is PodeHttp2Request http2Request)
            {
                var http2Response = new PodeHttp2Response(this);
                http2Response.StreamId = http2Request.StreamId;
                Response = http2Response;
            }
            else
            {
                Response = new PodeResponse(this);
            }
#else
            // netstandard2.0 only supports HTTP/1.x
            Response = new PodeResponse(this);
#endif
        }

        /// <summary>
        /// Creates a new request object based on the socket type and incoming data.
        /// </summary>
        /// <returns>A Task representing the async operation.</returns>
        private async Task NewRequest()
        {
            // Create a new request based on the socket type.
            switch (PodeSocket.Type)
            {
                case PodeProtocolType.Smtp:
                    Request = new PodeSmtpRequest(Socket, PodeSocket, this);
                    break;

                case PodeProtocolType.Tcp:
                    Request = new PodeTcpRequest(Socket, PodeSocket, this);
                    break;

                default:
                    // For HTTP sockets, detect if it's HTTP/1.x or HTTP/2
                    Request = await DetectHttpVersion().ConfigureAwait(false);
                    break;
            }

            // Attempt to open the request stream.
            await Request.Open(CancellationToken.None).ConfigureAwait(false);
            State = Request.State == PodeStreamState.Open
                ? PodeContextState.Open
                : PodeContextState.Error;

            // If the request is SMTP or TCP, send acknowledgment if available.
            if (IsOpened)
            {
                if (PodeSocket.IsSmtp)
                {
                    await SmtpRequest.SendAck().ConfigureAwait(false);
                }
                else if (PodeSocket.IsTcp && !string.IsNullOrWhiteSpace(PodeSocket.AcknowledgeMessage))
                {
                    await Response.WriteLine(PodeSocket.AcknowledgeMessage, true).ConfigureAwait(false);
                }
            }
        }        /// <summary>
                 /// Detects the HTTP version by checking ALPN negotiation and peeking at the incoming data.
                 /// </summary>
                 /// <returns>The appropriate PodeRequest object (HTTP/1.x or HTTP/2.0)</returns>
        private Task<PodeRequest> DetectHttpVersion()
        {
            try
            {
#if !NETSTANDARD2_0
                // Check if this is an HTTPS connection (SSL/TLS)
                var isSecure = PodeSocket?.IsSsl == true;

                if (isSecure)
                {
                    // For HTTPS connections, modern browsers negotiate HTTP/2 by default via ALPN
                    // We'll create an HTTP/2 request and let it handle ALPN negotiation
                    // If ALPN negotiates HTTP/1.1, the HTTP/2 request will handle it gracefully
                    PodeHelpers.WriteErrorMessage("HTTPS connection detected, defaulting to HTTP/2 with ALPN negotiation", Listener, PodeLoggingLevel.Debug, this);
                    return Task.FromResult<PodeRequest>(new PodeHttp2Request(Socket, PodeSocket, this));
                }

                // For HTTP connections, try to peek for HTTP/2 preface
                var buffer = new byte[24]; // HTTP/2 preface is 24 bytes
                var bytesReceived = PeekForHttp2Preface(buffer);

                if (bytesReceived > 0)
                {
                    var requestStart = System.Text.Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesReceived, 24));
                    PodeHelpers.WriteErrorMessage($"Peeked data: '{requestStart}' (length: {bytesReceived})", Listener, PodeLoggingLevel.Debug, this);

                    // First check for immediate "PRI" - this is always HTTP/2
                    if (requestStart.StartsWith("PRI"))
                    {
                        PodeHelpers.WriteErrorMessage("HTTP/2 preface detected (starts with PRI)", Listener, PodeLoggingLevel.Debug, this);
                        return Task.FromResult<PodeRequest>(new PodeHttp2Request(Socket, PodeSocket, this));
                    }

                    // Check for full HTTP/2 connection preface
                    if (bytesReceived >= 24 && IsHttp2ConnectionPreface(buffer, bytesReceived))
                    {
                        PodeHelpers.WriteErrorMessage("Full HTTP/2 connection preface detected", Listener, PodeLoggingLevel.Debug, this);
                        return Task.FromResult<PodeRequest>(new PodeHttp2Request(Socket, PodeSocket, this));
                    }

                    // Check for HTTP/2 upgrade request (h2c - HTTP/2 over cleartext)
                    if (IsHttp2UpgradeRequest(buffer, bytesReceived))
                    {
                        PodeHelpers.WriteErrorMessage("HTTP/2 upgrade request detected", Listener, PodeLoggingLevel.Debug, this);
                        // For upgrade requests, start with HTTP/1.1 and handle upgrade later
                        // TODO: Implement HTTP/2 upgrade handling
                        return Task.FromResult<PodeRequest>(new PodeHttpRequest(Socket, PodeSocket, this));
                    }

                    // Check for typical HTTP/1.x request methods
                    if (requestStart.StartsWith("GET ") || requestStart.StartsWith("POST ") ||
                        requestStart.StartsWith("PUT ") || requestStart.StartsWith("DELETE ") ||
                        requestStart.StartsWith("HEAD ") || requestStart.StartsWith("OPTIONS ") ||
                        requestStart.StartsWith("PATCH ") || requestStart.StartsWith("TRACE ") ||
                        requestStart.StartsWith("CONNECT "))
                    {
                        PodeHelpers.WriteErrorMessage("HTTP/1.x request method detected", Listener, PodeLoggingLevel.Debug, this);
                        return Task.FromResult<PodeRequest>(new PodeHttpRequest(Socket, PodeSocket, this));
                    }

                    // If we can't determine the protocol from the peeked data, log it for debugging
                    PodeHelpers.WriteErrorMessage($"Unrecognized request start, defaulting to HTTP/1.x: '{requestStart}'", Listener, PodeLoggingLevel.Debug, this);
                }
                else
                {
                    PodeHelpers.WriteErrorMessage("No data available for protocol detection, will use HTTP/1.x with fallback detection", Listener, PodeLoggingLevel.Debug, this);
                }
#endif

                // Default to HTTP/1.x with enhanced error detection
                PodeHelpers.WriteErrorMessage("Creating HTTP/1.x request with enhanced HTTP/2 fallback detection", Listener, PodeLoggingLevel.Debug, this);
                return Task.FromResult<PodeRequest>(new PodeHttpRequest(Socket, PodeSocket, this));
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteErrorMessage($"Error detecting HTTP version: {ex.Message}", Listener, PodeLoggingLevel.Warning, this);
                // Default to HTTP/1.x on error
                return Task.FromResult<PodeRequest>(new PodeHttpRequest(Socket, PodeSocket, this));
            }
        }

#if !NETSTANDARD2_0
        /// <summary>
        /// Attempts to peek at socket data with multiple strategies to detect HTTP/2 preface.
        /// </summary>
        /// <param name="buffer">Buffer to store peeked data</param>
        /// <returns>Number of bytes received</returns>
        private int PeekForHttp2Preface(byte[] buffer)
        {
            var maxAttempts = 5;
            var timeouts = new[] { 5, 20, 50, 100, 200 }; // Progressive timeouts in milliseconds

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    var bytesReceived = 0;

                    // First try: Check if data is immediately available
                    if (Socket.Available > 0)
                    {
                        bytesReceived = Socket.Receive(buffer, 0, Math.Min(buffer.Length, Socket.Available), SocketFlags.Peek);
                        PodeHelpers.WriteErrorMessage($"Attempt {attempt + 1}: Immediate peek got {bytesReceived} bytes", Listener, PodeLoggingLevel.Debug, this);

                        // If we got some data, check if it's enough or if we need more
                        if (bytesReceived >= 3) // At least "PRI"
                        {
                            var start = System.Text.Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesReceived, 3));
                            if (start == "PRI")
                            {
                                // This is definitely HTTP/2, but let's try to get the full preface if possible
                                if (bytesReceived < 24)
                                {
                                    // Wait a bit for more data to arrive and try again
                                    System.Threading.Thread.Sleep(10);
                                    if (Socket.Available >= 24)
                                    {
                                        var moreBytes = Socket.Receive(buffer, 0, 24, SocketFlags.Peek);
                                        if (moreBytes > bytesReceived)
                                        {
                                            bytesReceived = moreBytes;
                                            PodeHelpers.WriteErrorMessage($"Attempt {attempt + 1}: Got {bytesReceived} bytes total after waiting", Listener, PodeLoggingLevel.Debug, this);
                                        }
                                    }
                                }
                                return bytesReceived;
                            }
                        }

                        // If we have enough bytes for HTTP/1.x check, return them
                        if (bytesReceived >= 3)
                        {
                            return bytesReceived;
                        }
                    }

                    // Second try: Use blocking socket with progressive timeout to wait for data
                    if (bytesReceived == 0)
                    {
                        var originalBlocking = Socket.Blocking;
                        var originalTimeout = Socket.ReceiveTimeout;

                        try
                        {
                            Socket.Blocking = true;
                            Socket.ReceiveTimeout = timeouts[attempt];

                            bytesReceived = Socket.Receive(buffer, 0, buffer.Length, SocketFlags.Peek);
                            PodeHelpers.WriteErrorMessage($"Attempt {attempt + 1}: Blocking peek got {bytesReceived} bytes (timeout: {timeouts[attempt]}ms)", Listener, PodeLoggingLevel.Debug, this);
                        }
                        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                        {
                            // Timeout, continue to next attempt
                            PodeHelpers.WriteErrorMessage($"Attempt {attempt + 1}: Blocking peek timed out after {timeouts[attempt]}ms", Listener, PodeLoggingLevel.Debug, this);
                            bytesReceived = 0;
                        }
                        finally
                        {
                            Socket.Blocking = originalBlocking;
                            Socket.ReceiveTimeout = originalTimeout;
                        }
                    }

                    if (bytesReceived > 0)
                    {
                        return bytesReceived;
                    }
                }
                catch (Exception ex)
                {
                    PodeHelpers.WriteErrorMessage($"Attempt {attempt + 1}: Error during socket peek: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);
                }

                // Brief pause before next attempt (except on last attempt)
                if (attempt < maxAttempts - 1)
                {
                    System.Threading.Thread.Sleep(10);
                }
            }

            PodeHelpers.WriteErrorMessage("All peek attempts failed, no data available for protocol detection", Listener, PodeLoggingLevel.Debug, this);
            return 0;
        }
#endif

#if !NETSTANDARD2_0
        /// <summary>
        /// Checks if the incoming data contains the HTTP/2 connection preface.
        /// </summary>
        /// <param name="buffer">The buffer containing the incoming data</param>
        /// <param name="length">The number of bytes in the buffer</param>
        /// <returns>True if HTTP/2 preface is detected</returns>
        private bool IsHttp2ConnectionPreface(byte[] buffer, int length)
        {
            // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            var http2Preface = System.Text.Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

            if (length < http2Preface.Length)
            {
                return false;
            }

            for (int i = 0; i < http2Preface.Length; i++)
            {
                if (buffer[i] != http2Preface[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks if the incoming data contains an HTTP/2 upgrade request.
        /// </summary>
        /// <param name="buffer">The buffer containing the incoming data</param>
        /// <param name="length">The number of bytes in the buffer</param>
        /// <returns>True if HTTP/2 upgrade request is detected</returns>
        private bool IsHttp2UpgradeRequest(byte[] buffer, int length)
        {
            if (length < 20) return false; // Need minimum bytes to check

            var requestLine = System.Text.Encoding.ASCII.GetString(buffer, 0, Math.Min(length, 200));

            // Look for HTTP/2 upgrade indicators in the request
            return requestLine.Contains("HTTP/1.1") &&
                   (requestLine.Contains("Upgrade: h2c") ||
                    requestLine.Contains("Connection: Upgrade") ||
                    requestLine.Contains("HTTP2-Settings:"));
        }
#endif

        /// <summary>
        /// Sets the context type based on the request type and socket type.
        /// </summary>
        private void SetContextType()
        {
            if (!IsUnknown && !(base.IsHttp && Request.IsWebSocket))
            {
                return;
            }

            // Depending on socket type, set the appropriate protocol type.
            switch (PodeSocket.Type)
            {
                case PodeProtocolType.Smtp:
                    if (!Request.IsSmtp)
                    {
                        throw new PodeRequestException("Request is not Smtp", 422);
                    }
                    Type = PodeProtocolType.Smtp;
                    break;

                case PodeProtocolType.Tcp:
                    if (!Request.IsTcp)
                    {
                        throw new PodeRequestException("Request is not Tcp", 422);
                    }
                    Type = PodeProtocolType.Tcp;
                    break;

                case PodeProtocolType.Http:
                    if (Request.IsWebSocket)
                    {
                        throw new PodeRequestException("Request is not Http", 422);
                    }
                    // Handle both HTTP/1.x and HTTP/2
                    if (!(Request is PodeHttpRequest
#if !NETSTANDARD2_0
                            || Request is PodeHttp2Request
#endif
                         ))
                    {
                        throw new PodeRequestException("Request is not Http", 422);
                    }
                    Type = PodeProtocolType.Http;
                    break;

                case PodeProtocolType.Ws:
                    if (!Request.IsWebSocket)
                    {
                        throw new PodeRequestException("Request is not for a WebSocket", 422);
                    }
                    Type = PodeProtocolType.Ws;
                    break;

                case PodeProtocolType.HttpAndWs:
                    Type = Request.IsWebSocket ? PodeProtocolType.Ws : PodeProtocolType.Http;
                    break;
            }
        }

        /// <summary>
        /// Cancels the request timeout by disposing of the timeout timer.
        /// </summary>
        public void CancelTimeout()
        {
            TimeoutTimer?.Dispose();
            TimeoutTimer = null;
        }

        /// <summary>
        /// Handles receiving data for the current request.
        /// </summary>
        /// <returns>A Task representing the async operation.</returns>
        public async Task Receive()
        {
            try
            {
                // Start timeout - unless receiving a WebSocket request.
                ContextTimeoutToken = new CancellationTokenSource();
                if (!IsWebSocketUpgraded)
                {
                    TimeoutTimer = new Timer(TimeoutCallback, null, Listener.RequestTimeout * 1000, Timeout.Infinite);
                }

                // Start receiving data.
                State = PodeContextState.Receiving;

                try
                {
                    PodeHelpers.WriteErrorMessage($"Receiving request", Listener, PodeLoggingLevel.Verbose, this);
                    var close = await Request.Receive(ContextTimeoutToken.Token).ConfigureAwait(false);
                    SetContextType();
                    await EndReceive(close).ConfigureAwait(false);
                }
#if !NETSTANDARD2_0
                catch (PodeRequestException ex) when (ex.StatusCode == 422 && ex.Message.Contains("protocol detection issue"))
                {
                    PodeHelpers.WriteErrorMessage($"Protocol detection issue detected, retrying with HTTP/1.1: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);

                    // Create a new HTTP/1.1 request to replace the failed HTTP/2 request
                    var http11Request = new PodeHttpRequest(Socket, PodeSocket, this);

                    // Transfer properties from the failed request (if any)
                    if (Request != null)
                    {
                        // Dispose the old request
                        Request.Dispose();
                    }

                    // Set the new request
                    Request = http11Request;
                    
                    // Also create a new HTTP/1.1 response to replace the HTTP/2 response
                    if (Response != null)
                    {
                        Response.Dispose();
                    }
                    Response = new PodeResponse(this);

                    // Try opening the new request
                    await Request.Open(CancellationToken.None).ConfigureAwait(false);

                    // Try receiving again with HTTP/1.1
                    var close = await Request.Receive(ContextTimeoutToken.Token).ConfigureAwait(false);
                    SetContextType();
                    await EndReceive(close).ConfigureAwait(false);
                }
#endif
                catch (Exception ex) when (ex is IOException || ex is SocketException)
                {
                    // ignore if listener is closing, else re-throw
                    if (Listener.IsConnected)
                    {
                        throw;
                    }
                }
                catch (OperationCanceledException ex) when (ContextTimeoutToken.IsCancellationRequested)
                {
                    PodeHelpers.WriteErrorMessage("Request timed out during receive operation", Listener, PodeLoggingLevel.Warning, this);
                    State = PodeContextState.Timeout;  // Explicitly set the state to Timeout
                    Request.Error = new PodeRequestException("Request timed out", ex, 408);
                }
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, Listener, PodeLoggingLevel.Debug);
                State = PodeContextState.Error;
                await PodeSocket.HandleContext(this).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Ends the receiving process and handles the context based on whether it should be closed.
        /// </summary>
        /// <param name="close">Whether the context should be closed after receiving.</param>
        /// <returns>A Task representing the async operation.</returns>
        public async Task EndReceive(bool close)
        {
            State = close ? PodeContextState.Closing : PodeContextState.Received;
            if (close)
            {
                Response.StatusCode = 400;
            }

            await PodeSocket.HandleContext(this).ConfigureAwait(false);
        }

        /// <summary>
        /// Starts receiving data by creating a new response and setting the state.
        /// </summary>
        public void StartReceive()
        {
            NewResponse();
            State = PodeContextState.Receiving;
            PodeSocket.StartReceive(this);
            PodeHelpers.WriteErrorMessage($"Socket listening", Listener, PodeLoggingLevel.Verbose, this);
        }

        /// <summary>
        /// Upgrades the connection to a WebSocket.
        /// </summary>
        /// <param name="clientId">The client identifier for the WebSocket connection.</param>
        /// <returns>A Task representing the async operation.</returns>
        /// <exception cref="PodeRequestException">Thrown if the request cannot be upgraded to a WebSocket.</exception>
        public async Task UpgradeWebSocket(string clientId = null)
        {
            PodeHelpers.WriteErrorMessage($"Upgrading Websocket", Listener, PodeLoggingLevel.Verbose, this);

            if (!IsWebSocket)
            {
                throw new PodeRequestException("Cannot upgrade a non-websocket request", 412);
            }

            // Set a default clientId if none is provided.
            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = PodeHelpers.NewGuid();
            }

            // Set the status of the response to indicate protocol switching.
            Response.StatusCode = 101;
            Response.StatusDescription = "Switching Protocols";

            // Get the socket key from the request.
            var socketKey = $"{HttpRequest.Headers["Sec-WebSocket-Key"]}".Trim();

            // Create the socket accept hash.
            var crypto = SHA1.Create();
            var socketHash = Convert.ToBase64String(crypto.ComputeHash(System.Text.Encoding.UTF8.GetBytes($"{socketKey}{PodeHelpers.WEB_SOCKET_MAGIC_KEY}")));

            // Compile headers for the response.
            Response.Headers.Clear();
            Response.Headers.Set("Connection", "Upgrade");
            Response.Headers.Set("Upgrade", "websocket");
            Response.Headers.Set("Sec-WebSocket-Accept", socketHash);

            if (!string.IsNullOrWhiteSpace(clientId))
            {
                Response.Headers.Set("X-Pode-ClientId", clientId);
            }

            // Send response to upgrade to WebSocket.
            await Response.Send().ConfigureAwait(false);

            // Cancel the timeout timer before upgrading.
            CancelTimeout();

            // Add the upgraded WebSocket to the listener.
            var signal = new PodeSignal(this, HttpRequest.Url.AbsolutePath, clientId);
            Request = new PodeSignalRequest(HttpRequest, signal);
            Listener.AddSignal(SignalRequest.Signal);
            PodeHelpers.WriteErrorMessage($"Websocket upgraded", Listener, PodeLoggingLevel.Verbose, this);
        }

        /// <summary>
        /// Disposes of the resources used by the context.
        /// </summary>
        public void Dispose()
        {
            Dispose(Request.Error != default(PodeRequestException));
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of the resources used by the context, with an option to force disposal.
        /// </summary>
        /// <param name="force">Whether to force the disposal of resources.</param>
        public void Dispose(bool force)
        {
            lock (_lockable)
            {
                PodeHelpers.WriteErrorMessage($"Disposing Context", Listener, PodeLoggingLevel.Verbose, this);
                Listener.RemoveProcessingContext(this);

                if (IsClosed)
                {
                    PodeSocket.RemovePendingSocket(Socket);
                    Request?.Dispose();
                    Response?.Dispose();
                    DisposeTimeoutResources();
                    return;
                }

                var _awaitingBody = false;

                try
                {
                    // Dispose timeout resources
                    DisposeTimeoutResources();

                    // Set error status code if context is errored.
                    if (IsErrored)
                    {
                        Response.StatusCode = Request.IsAborted ? Request.Error.StatusCode : 500;
                    }

                    // Determine if the HTTP request is awaiting more data.
                    if (IsHttp)
                    {
                        if (Request is PodeHttpRequest httpRequest)
                        {
                            _awaitingBody = httpRequest.AwaitingBody && !IsErrored && !IsTimeout;
                        }
#if !NETSTANDARD2_0
                        else if (Request is PodeHttp2Request http2Request)
                        {
                            _awaitingBody = http2Request.AwaitingBody && !IsErrored && !IsTimeout;
                        }
#endif
                    }

                    // Send response if HTTP and not awaiting body.
                    if (IsHttp && Request.IsOpen && !_awaitingBody)
                    {
                        if (IsTimeout)
                        {
                            Response.SendTimeout().Wait();
                        }
                        else
                        {
                            Response.Send().Wait();
                        }
                    }

                    // Reset SMTP request if it was processable.
                    if (IsSmtp && Request.IsProcessable)
                    {
                        SmtpRequest.Reset();
                    }

                    // Dispose of request and response if not keep-alive or forced.
                    if (!_awaitingBody && (!IsKeepAlive || force))
                    {
                        State = PodeContextState.Closed;

                        if (Response.SseEnabled)
                        {
                            Response.CloseSseConnection().Wait();
                        }

                        Request.Dispose();
                    }

                    if (!IsWebSocket || force)
                    {
                        Response.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    PodeHelpers.WriteException(ex, Listener, PodeLoggingLevel.Error);
                }
                finally
                {
                    // Handle re-receiving or socket clean-up.
                    if ((_awaitingBody || (IsKeepAlive && !IsErrored && !IsTimeout && !Response.SseEnabled)) && !force)
                    {
                        PodeHelpers.WriteErrorMessage($"Re-receiving Request", Listener, PodeLoggingLevel.Verbose, this);
                        StartReceive();
                    }
                    else
                    {
                        PodeSocket.RemovePendingSocket(Socket);
                    }
                }
            }
        }

        /// <summary>
        /// Disposes timeout-related resources.
        /// </summary>
        private void DisposeTimeoutResources()
        {
            ContextTimeoutToken?.Dispose();
            TimeoutTimer?.Dispose();
            ContextTimeoutToken = null;
            TimeoutTimer = null;
        }
    }
}