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
#if NETCOREAPP2_1_OR_GREATER
        public new bool IsHttp => base.IsHttp || (IsUnknown && PodeSocket.IsHttp)|| IsHttp2;
        // Determines if the context is associated with HTTP/2.
        public bool IsHttp2 => Request is PodeHttp2Request;
#else
        public new bool IsHttp => base.IsHttp || (IsUnknown && PodeSocket.IsHttp);
#endif

        // Strongly typed request properties for different protocols.
        public PodeSmtpRequest SmtpRequest => (PodeSmtpRequest)Request;
        public PodeHttp1xRequest HttpRequest => Request as PodeHttp1xRequest ??
            throw new InvalidOperationException("Request is not HTTP/1.x");
#if NETCOREAPP2_1_OR_GREATER
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
#if NETCOREAPP2_1_OR_GREATER
            // Create HTTP/2 response if the request is HTTP/2, otherwise use standard response
            if (Request is PodeHttp2Request http2Request)
            {
                Console.WriteLine($"[DEBUG] Creating HTTP/2 response for stream {http2Request.StreamId} in NewResponse()");
                PodeHelpers.WriteErrorMessage($"DEBUG: Creating HTTP/2 response for stream {http2Request.StreamId}", Listener, PodeLoggingLevel.Verbose, this);
                Response = new PodeHttp2Response(http2Request);

                Console.WriteLine($"[DEBUG] HTTP/2 response created successfully with StreamId: {http2Request.StreamId}, Type: {Response.GetType().Name}");
                PodeHelpers.WriteErrorMessage($"DEBUG: HTTP/2 response created successfully", Listener, PodeLoggingLevel.Verbose, this);
            }
            else
            {
                Console.WriteLine($"[DEBUG] Creating HTTP/1.x response (Request type: {Request?.GetType().Name}) in NewResponse()");
                PodeHelpers.WriteErrorMessage($"DEBUG: Creating HTTP/1.x response (Request type: {Request?.GetType().Name})", Listener, PodeLoggingLevel.Verbose, this);
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
#if NETCOREAPP2_1_OR_GREATER


                    Request = await DetectHttpVersion().ConfigureAwait(false);

                    /*
                       bool alpnNegotiatedHttp2 = false;
                      Console.WriteLine("[DEBUG] Creating HTTP/1.1 request");
                              var httpRequest = new PodeHttpRequest(Socket, PodeSocket, this);
                              await httpRequest.Open(CancellationToken.None).ConfigureAwait(false);


                              Console.WriteLine($"[DEBUG] ALPN negotiated protocol: {alpnNegotiatedHttp2}");
                              if (PodeSocket?.IsSsl == true)
                              {
                                  if (Data.ContainsKey("AlpnNegotiatedHttp2"))
                                  {
                                      Console.WriteLine("[DEBUG] ALPN negotiated HTTP/2, using PodeHttp2Request");
                                          Request = new PodeHttp2Request(httpRequest);

                                      return;
                                      // httpRequest.Dispose();
                                  }
                                  else
                                  {
                                       Request = httpRequest;
                                       return;
                                  }
                              }
                              else
                              {
                                  Console.WriteLine("[DEBUG] ALPN did NOT negotiate HTTP/2, using DetectHttpVersion");
                                  // Use DetectHttpVersion to sniff for HTTP/2 preface, even on SSL!
                                  Request = await DetectHttpVersion().ConfigureAwait(false);
                              }*/


#else
                    Console.WriteLine("[DEBUG] Creating HTTP/1.1 request");
                    Request = new PodeHttp1xRequest(Socket, PodeSocket, this);
#endif
                    Console.WriteLine($"[DEBUG] Request created: {Request.GetType().Name}");
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
        }
#if NETCOREAPP2_1_OR_GREATER

        /// <summary>
        /// Detects the HTTP version by checking ALPN negotiation and peeking at the incoming data.
        /// </summary>
        /// <returns>The appropriate PodeRequest object (HTTP/1.x or HTTP/2.0)</returns>
        private Task<PodeRequest> DetectHttpVersion()
        {
            Console.WriteLine("[DEBUG] DetectHttpVersion() called");
            try
            {
                var isSecure = PodeSocket?.IsSsl == true;
                Console.WriteLine($"[DEBUG] IsSecure: {isSecure}");

                // Always peek for the HTTP/2 preface
                var buffer = new byte[24]; // HTTP/2 preface is 24 bytes
                var bytesReceived = PeekForHttp2PrefaceNonBlocking(buffer);

                if (bytesReceived > 0)
                {
                    var requestStart = System.Text.Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesReceived, 24));
                    Console.WriteLine($"[DEBUG] Peeked data: '{requestStart}' (length: {bytesReceived})");

                    // HTTP/2 detection: if first 3 bytes are "PRI", always treat as HTTP/2
                    if (requestStart.StartsWith("PRI"))
                    {
                        Console.WriteLine("[DEBUG] Detected 'PRI', using PodeHttp2Request");
                        return Task.FromResult<PodeRequest>(new PodeHttp2Request(Socket, PodeSocket, this));
                    }

                    // Full HTTP/2 connection preface
                    if (bytesReceived >= 24 && IsHttp2ConnectionPreface(buffer, bytesReceived))
                    {
                        Console.WriteLine("[DEBUG] Full HTTP/2 connection preface detected");
                        return Task.FromResult<PodeRequest>(new PodeHttp2Request(Socket, PodeSocket, this));
                    }

                    // (h2c upgrade and HTTP/1.x only possible for cleartext)
                    if (!isSecure && IsHttp2UpgradeRequest(buffer, bytesReceived))
                    {
                        Console.WriteLine("[DEBUG] HTTP/2 upgrade request detected");
                        return Task.FromResult<PodeRequest>(new PodeHttp1xRequest(Socket, PodeSocket, this));
                    }

                    // HTTP/1.x request detection
                    if (requestStart.StartsWith("GET ") || requestStart.StartsWith("POST ") ||
                        requestStart.StartsWith("PUT ") || requestStart.StartsWith("DELETE ") ||
                        requestStart.StartsWith("HEAD ") || requestStart.StartsWith("OPTIONS ") ||
                        requestStart.StartsWith("PATCH ") || requestStart.StartsWith("TRACE ") ||
                        requestStart.StartsWith("CONNECT "))
                    {
                        Console.WriteLine("[DEBUG] HTTP/1.x request method detected");
                        return Task.FromResult<PodeRequest>(new PodeHttp1xRequest(Socket, PodeSocket, this));
                    }

                    Console.WriteLine($"[DEBUG] Unrecognized request start: '{requestStart}', treating as HTTP/1.x for safety");
                }
                else
                {
                    Console.WriteLine("[DEBUG] No data available for protocol detection, treating as HTTP/1.x");
                }

                // Default/fallback: HTTP/1.x request
                return Task.FromResult<PodeRequest>(new PodeHttp1xRequest(Socket, PodeSocket, this));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Error detecting HTTP version: {ex.Message}");
                return Task.FromResult<PodeRequest>(new PodeHttp1xRequest(Socket, PodeSocket, this));
            }
        }

        /// <summary>
        /// Attempts to peek at socket data using non-blocking approach to detect HTTP/2 preface.
        /// </summary>
        /// <param name="buffer">Buffer to store peeked data</param>
        /// <returns>Number of bytes received</returns>
        private int PeekForHttp2PrefaceNonBlocking(byte[] buffer)
        {
            try
            {
                // First, check if any data is immediately available
                if (Socket.Available > 0)
                {
                    var bytesReceived = Socket.Receive(buffer, 0, Math.Min(buffer.Length, Socket.Available), SocketFlags.Peek);
                    PodeHelpers.WriteErrorMessage($"Non-blocking peek got {bytesReceived} bytes immediately", Listener, PodeLoggingLevel.Debug, this);
                    return bytesReceived;
                }

                // If no data is immediately available, wait a short time
                var waitTime = 50; // 50ms timeout
                var startTime = DateTime.UtcNow;

                while ((DateTime.UtcNow - startTime).TotalMilliseconds < waitTime)
                {
                    if (Socket.Available > 0)
                    {
                        var bytesReceived = Socket.Receive(buffer, 0, Math.Min(buffer.Length, Socket.Available), SocketFlags.Peek);
                        PodeHelpers.WriteErrorMessage($"Non-blocking peek got {bytesReceived} bytes after waiting", Listener, PodeLoggingLevel.Debug, this);
                        return bytesReceived;
                    }

                    // Brief sleep to avoid busy waiting
                    System.Threading.Thread.Sleep(5);
                }

                PodeHelpers.WriteErrorMessage("Non-blocking peek timed out, no data available", Listener, PodeLoggingLevel.Debug, this);
                return 0;
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteErrorMessage($"Error during non-blocking socket peek: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);
                return 0;
            }
        }

        /// <summary>
        /// Gets the ALPN negotiated protocol from the TLS connection.
        /// </summary>
        /// <returns>The negotiated protocol string, or null if not available</returns>
        private string GetAlpnNegotiatedProtocol()
        {
            try
            {
                // TODO: Implement ALPN negotiation detection
                // This would require access to the SSL/TLS stream to get the negotiated protocol
                // For now, return null to indicate ALPN is not implemented
                return null;
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteErrorMessage($"Error getting ALPN negotiated protocol: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);
                return null;
            }
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
                    if (!(Request is PodeHttp1xRequest
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


#if NETCOREAPP2_1_OR_GREATER
        public async Task UpgradeAsync( )
        {
            Console.WriteLine("[DEBUG] 🔄 HTTP/2 upgrade - switching from HTTP/1.1 to HTTP/2 parser");

            // Extract any buffered preface data from the HTTP/1.1 Request before disposing
            byte[] prefaceData = null;
            if (Request != null && Data.ContainsKey("Http2PrefaceData"))
            {
                prefaceData = (byte[])Data["Http2PrefaceData"];
                Console.WriteLine($"[DEBUG] Retrieved {prefaceData?.Length ?? 0} bytes of preface data from HTTP/1.1 parser");
            }

            // DON'T dispose the current HTTP/1.1 Request yet - we need to preserve the socket and SSL stream
            // Instead, we'll "detach" the socket and input stream from the old Request so they don't get disposed
            var oldRequest = Request;
            Request = null;

            // Extract the socket and InputStream from the old Request before detaching
            Socket preservedSocket = null;
            Stream preservedInputStream = null;

            if (oldRequest != null)
            {
                // Use reflection to access the private socket field, but direct access for InputStream
                var socketField = typeof(PodeRequest).GetField("Socket", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                Console.WriteLine($"[DEBUG] Reflection results: socketField={socketField != null}");

                if (socketField != null)
                {
                    preservedSocket = (Socket)socketField.GetValue(oldRequest);
                    preservedInputStream = oldRequest.InputStream; // Direct access now that setter is internal

                    Console.WriteLine($"[DEBUG] Extracted values: socket={preservedSocket != null}, inputStream={preservedInputStream != null}");
                    Console.WriteLine($"[DEBUG] Socket Connected: {preservedSocket?.Connected}, InputStream Type: {preservedInputStream?.GetType().Name}");

                    // Clear socket field and InputStream property so disposal doesn't close them
                    socketField.SetValue(oldRequest, null);
                    oldRequest.InputStream = null; // Direct assignment now that setter is internal
                    Console.WriteLine("[DEBUG] Detached socket and InputStream from old HTTP/1.1 Request");
                }
                else
                {
                    Console.WriteLine("[DEBUG] ❌ Failed to get socket field via reflection");
                }
            }

            // Create a new HTTP/2 Request to handle this connection
            Console.WriteLine("[DEBUG] About to create PodeHttp2Request...");
            try
            {
                // Use the preserved socket instead of the context's Socket to avoid disposed socket issues
                var socketToUse = preservedSocket ?? Socket;
                Console.WriteLine($"[DEBUG] Using socket for HTTP/2 Request: preserved={preservedSocket != null}, context={Socket != null}");
                Request = new PodeHttp2Request(socketToUse, PodeSocket, this);
                Console.WriteLine("[DEBUG] PodeHttp2Request created successfully");

                // Transfer the preserved InputStream to the new HTTP/2 Request
                if (preservedInputStream != null)
                {
                    Request.InputStream = preservedInputStream; // Direct assignment now that setter is internal
                    Console.WriteLine("[DEBUG] Transferred preserved InputStream to HTTP/2 Request");
                }
            }
            catch (Exception constructorEx)
            {
                Console.WriteLine($"[DEBUG] ❌ Failed to create PodeHttp2Request: {constructorEx.GetType().Name}: {constructorEx.Message}");

                // If HTTP/2 Request creation failed, dispose the old Request and re-throw
                if (oldRequest != null)
                {
                    oldRequest.Dispose();
                }
                throw;
            }

            // If HTTP/2 Request creation succeeded, we can now safely dispose the old HTTP/1.1 Request
            // (it won't close the socket since we detached it)
            if (oldRequest != null)
            {
                oldRequest.Dispose();
                Console.WriteLine("[DEBUG] Disposed old HTTP/1.1 Request (socket was detached)");
            }

            // Pass the preface data to the HTTP/2 Request if available
            if (prefaceData != null)
            {
                Data["Http2PrefaceData"] = prefaceData;
                Console.WriteLine($"[DEBUG] Passed {prefaceData.Length} bytes of preface data to HTTP/2 parser");
            }

            // Also update the response to be compatible with HTTP/2
            if (Response != null)
            {
                Response.Dispose();
            }
            // Create HTTP/2 response for the HTTP/2 Request
            if (Request is PodeHttp2Request http2Request)
            {
                var http2Response = new PodeHttp2Response((PodeHttp2Request)Request);
                Console.WriteLine($"[DEBUG] Created HTTP/2 response for stream {http2Request.StreamId}");
                Response = http2Response;
            }
            else
            {
                // Fallback to standard response if not HTTP/2 Request
                Response = new PodeResponse(this);
                Console.WriteLine("[DEBUG] Fallback to standard PodeResponse for HTTP/1.x Request");
            }


            // Try opening the new HTTP/2 Request
            Console.WriteLine("[DEBUG] About to call Request.Open() on HTTP/2 Request...");
            await Request.Open(CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine("[DEBUG] Request.Open() completed successfully");

            // Try receiving again with HTTP/2 (the HTTP/2 parser will handle the preface)
            Console.WriteLine("[DEBUG] About to call Request.Receive() on HTTP/2 Request...");
            var close = await Request.Receive(ContextTimeoutToken.Token).ConfigureAwait(false);
            Console.WriteLine("[DEBUG] Request.Receive() completed successfully");

            // Update the HTTP/2 response with the correct stream ID after the Request is processed
            if (Response is PodeHttp2Response http2ResponseUpdate && Request is PodeHttp2Request http2RequestUpdate)
            {
                http2ResponseUpdate.StreamId = http2RequestUpdate.StreamId;
                Console.WriteLine($"[DEBUG] Updated HTTP/2 response stream ID to {http2RequestUpdate.StreamId}");
            }

            SetContextType();
            await EndReceive(close).ConfigureAwait(false);
        }
#endif

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
#if NETCOREAPP2_1_OR_GREATER
                catch (PodeRequestException ex) when (ex.StatusCode == 422 && ex.Message == "HTTP_2_UPGRADE_REQUIRED")
                {


                    Console.WriteLine("[DEBUG] 🔄 HTTP/2 upgrade required - switching from HTTP/1.1 to HTTP/2 parser");
                    PodeHelpers.WriteErrorMessage("HTTP/2 upgrade required, switching parser", Listener, PodeLoggingLevel.Debug, this);
                    // Upgrade to HTTP/2 parser
                    await UpgradeAsync( ).ConfigureAwait(false);

                }
                catch (PodeRequestException ex) when (ex.StatusCode == 422 && ex.Message.Contains("protocol detection issue"))
                {
                    PodeHelpers.WriteErrorMessage($"Protocol detection issue detected, closing with GOAWAY: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);

                    // If the request is HTTP/2 (ALPN negotiated h2), send GOAWAY and close
                    if (Data.ContainsKey("AlpnNegotiatedHttp2") && Data["AlpnNegotiatedHttp2"] is bool b && b && Request is PodeHttp2Request http2Req)
                    {
                        await http2Req.SendGoAwayAsync(0, Http2ErrorCode.ProtocolError, "Invalid HTTP/2 connection preface", ContextTimeoutToken.Token);
                        await http2Req.CloseConnection(ContextTimeoutToken.Token);
                        State = PodeContextState.Closed;
                        return;
                    }
                    Console.WriteLine("[DEBUG] Fallback to HTTP/1.1 due to protocol detection issue");
                    // If not HTTP/2, fallback to HTTP/1.1 request
                    PodeHelpers.WriteErrorMessage($"Fallback to HTTP/1.1 due to protocol detection issue: {ex.Message}", Listener, PodeLoggingLevel.Debug, this);
                    // Else, only fallback to HTTP/1.1 if not ALPN negotiated h2 (very rare, mostly cleartext)
                    var http11Request = new PodeHttp1xRequest(Socket, PodeSocket, this);
                    Request?.Dispose();
                    Request = http11Request;
                    Response?.Dispose();
                    Response = new PodeResponse(this);
                    await Request.Open(CancellationToken.None).ConfigureAwait(false);
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
                        if (Request is PodeHttp1xRequest httpRequest)
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