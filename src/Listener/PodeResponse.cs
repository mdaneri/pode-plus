using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Pode
{
    public class PodeResponse : IDisposable
    {
        protected const int MAX_FRAME_SIZE = 8192;

        // “Small” files up to 64 MiB get buffered in-memory; anything larger is streamed.
        private const long MAX_IN_MEMORY_FILE_SIZE = 64L * 1024 * 1024;

        public PodeResponseHeaders Headers { get; private set; }
        public int StatusCode = 200;
        public bool SendChunked = false;
        public MemoryStream OutputStream { get; private set; }
        public bool IsDisposed { get; private set; }

        private readonly PodeContext Context;
        private PodeRequest Request { get => Context.Request; }

        public PodeSseScope SseScope { get; private set; } = PodeSseScope.None;
        public bool SseEnabled
        {
            get => SseScope != PodeSseScope.None;
        }

        public bool SentHeaders { get; private set; }
        public bool SentBody { get; private set; }
        public bool Sent
        {
            get => SentHeaders && SentBody;
        }

        private string _statusDesc = string.Empty;
        public string StatusDescription
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_statusDesc) && Enum.IsDefined(typeof(HttpStatusCode), StatusCode))
                {
                    return ((HttpStatusCode)StatusCode).ToString();
                }

                return _statusDesc;
            }
            set => _statusDesc = value;
        }

        public long ContentLength64
        {
            get
            {
                if (!Headers.ContainsKey("Content-Length"))
                {
                    return 0;
                }

                return long.Parse($"{Headers["Content-Length"]}");
            }
            set
            {
                Headers.Set("Content-Length", value);
            }
        }

        public string ContentType
        {
            get => $"{Headers["Content-Type"]}";
            set => Headers.Set("Content-Type", value);
        }

        public string HttpResponseLine
        {
            get => $"{((PodeHttpRequest)Request).Protocol} {StatusCode} {StatusDescription}{PodeHelpers.NEW_LINE}";
        }

        private static readonly UTF8Encoding Encoding = new UTF8Encoding();

        /// <summary>
        /// PodeResponse class represents an HTTP response in the Pode framework.
        /// It encapsulates the response headers, status code, output stream, and methods to send the response.
        /// </summary>
        /// <param name="context"></param>
        public PodeResponse(PodeContext context)
        {
            Headers = new PodeResponseHeaders();
            OutputStream = new MemoryStream();
            Context = context;
        }

        /// <summary>
        /// Creates a new PodeResponse instance by copying the properties from another PodeResponse instance.
        /// This is useful for creating a response that is similar to an existing one, such as in a middleware scenario.
        /// </summary>
        /// <param name="other"></param>
        public PodeResponse(PodeResponse other)
        {
            // Copy the status code and other scalar values
            StatusCode = other.StatusCode;
            SendChunked = other.SendChunked;
            IsDisposed = other.IsDisposed;
            SseScope = other.SseScope;
            SentHeaders = other.SentHeaders;
            SentBody = other.SentBody;
            _statusDesc = other._statusDesc;

            // Create a new memory stream and copy the content of the other stream
            OutputStream = new MemoryStream();
            other.OutputStream.CopyTo(OutputStream);

            // Copy the headers (assuming PodeResponseHeaders supports cloning or deep copy)
            Headers = new PodeResponseHeaders();
            foreach (var key in other.Headers.Keys)
            {
                Headers.Set(key, other.Headers[key]);
            }

            // Copy the context and request, or create new instances if necessary (context should probably be reused)
            Context = other.Context;
        }


        /// <summary>
        /// Sends the complete HTTP response, including headers and body, to the client.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task Send()
        {
            if (Sent || IsDisposed || (SentHeaders && SseEnabled))
            {
                return;
            }

            PodeHelpers.WriteErrorMessage($"Sending response", Context.Listener, PodeLoggingLevel.Verbose, Context);

            try
            {
                await SendHeaders(Context.IsTimeout).ConfigureAwait(false);
                await SendBody(Context.IsTimeout).ConfigureAwait(false);
                PodeHelpers.WriteErrorMessage($"Response sent", Context.Listener, PodeLoggingLevel.Verbose, Context);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (AggregateException aex)
            {
                PodeHelpers.HandleAggregateException(aex, Context.Listener);
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, Context.Listener);
                throw;
            }
            finally
            {
                await Flush().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Sends a timeout (408) response when the client times out.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task SendTimeout()
        {
            if (SentHeaders || IsDisposed)
            {
                return;
            }

            PodeHelpers.WriteErrorMessage($"Sending response timed-out", Context.Listener, PodeLoggingLevel.Verbose, Context);
            StatusCode = 408;

            try
            {
                await SendHeaders(true).ConfigureAwait(false);
                PodeHelpers.WriteErrorMessage($"Response timed-out sent", Context.Listener, PodeLoggingLevel.Verbose, Context);
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (AggregateException aex)
            {
                PodeHelpers.HandleAggregateException(aex, Context.Listener);
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, Context.Listener);
                throw;
            }
            finally
            {
                await Flush().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Sends the HTTP headers to the client.
        /// If `timeout` is true, it clears existing headers and sets default headers.
        /// </summary>
        /// <param name="timeout"></param>
        /// <returns></returns>
        private async Task SendHeaders(bool timeout)
        {
            if (SentHeaders || !Request.InputStream.CanWrite)
            {
                return;
            }

            // default headers
            if (timeout)
            {
                Headers.Clear();
            }

            SetDefaultHeaders();

            // stream response output
            var buffer = Encoding.GetBytes(BuildHeaders(Headers));
            await Request.InputStream.WriteAsync(buffer, 0, buffer.Length, Context.Listener.CancellationToken).ConfigureAwait(false);
            buffer = default;
            SentHeaders = true;
        }

        private async Task SendBody(bool timeout)
        {
            if (SentBody || SseEnabled || !Request.InputStream.CanWrite)
            {
                return;
            }

            // stream response output
            if (!timeout && OutputStream.Length > 0)
            {
                await Task.Run(() => OutputStream.WriteTo(Request.InputStream), Context.Listener.CancellationToken).ConfigureAwait(false);
            }

            SentBody = true;
        }

        /// <summary>
        /// Flushes the response stream to the client.
        /// This method ensures that any buffered data is sent to the client immediately.
        /// It checks if the input stream can be written to before attempting to flush.
        /// If the input stream is not writable, it does nothing.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task Flush()
        {
            if (Request.InputStream.CanWrite)
            {
                await Request.InputStream.FlushAsync().ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Establishes an SSE (Server-Sent Events) connection with appropriate headers.
        /// This method sets the SSE scope, client ID, name, group, retry interval, and allows cross-origin requests if specified.
        /// It sends the initial headers and an open event to the client, and caches the connection if the scope is global.
        /// </summary>
        /// <param name="scope">Scope of the SSE (Local/Global).</param>
        /// <param name="clientId">Optional SSE client ID.</param>
        /// <param name="name">Name of the connection.</param>
        /// <param name="group">Group the SSE connection belongs to.</param>
        /// <param name="retry">Reconnect retry interval (ms).</param>
        /// <param name="allowAllOrigins">Allow cross-origin requests.</param>
        /// <param name="asyncRouteTaskId">Async route task ID (optional).</param>
        /// <returns>The client ID used for the SSE connection.</returns>
        public async Task<string> SetSseConnection(PodeSseScope scope, string clientId, string name, string group, int retry, bool allowAllOrigins, string asyncRouteTaskId = null)
        {
            // do nothing for no scope
            if (scope == PodeSseScope.None)
            {
                return null;
            }

            // cancel timeout
            Context.CancelTimeout();
            SseScope = scope;

            // set appropriate SSE headers
            Headers.Clear();
            ContentType = "text/event-stream";
            Headers.Add("Cache-Control", "no-cache");
            Headers.Add("Connection", "keep-alive");

            if (allowAllOrigins)
            {
                Headers.Add("Access-Control-Allow-Origin", "*");
            }

            // generate clientId
            if (string.IsNullOrEmpty(clientId))
            {
                clientId = PodeHelpers.NewGuid();
            }

            Headers.Set("X-Pode-Sse-Client-Id", clientId);
            Headers.Set("X-Pode-Sse-Name", name);

            if (!string.IsNullOrEmpty(group))
            {
                Headers.Set("X-Pode-Sse-Group", group);
            }

            // send headers, and open event
            await Send().ConfigureAwait(false);
            await SendSseRetry(retry).ConfigureAwait(false);
            string sseEvent = (string.IsNullOrEmpty(asyncRouteTaskId)) ?
            $"{{\"clientId\":\"{clientId}\",\"group\":\"{group}\",\"name\":\"{name}\"}}" :
            $"{{\"clientId\":\"{clientId}\",\"group\":\"{group}\",\"name\":\"{name}\",\"asyncRouteTaskId\":\"{asyncRouteTaskId}\"}}";

            await SendSseEvent("pode.open", sseEvent).ConfigureAwait(false);

            // if global, cache connection in listener
            if (scope == PodeSseScope.Global)
            {
                Context.Listener.AddSseConnection(new PodeServerEvent(Context, name, group, clientId));
            }

            // return clientId
            return clientId;
        }

        /// <summary>
        /// Sends a "close" SSE event to the client to terminate the connection.
        /// This method is typically used to gracefully close an SSE connection.
        /// It sends an event with the type "pode.close" and no data, indicating that the server is closing the connection.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task CloseSseConnection()
        {
            await SendSseEvent("pode.close", string.Empty).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a named SSE event with optional ID.
        /// This method allows sending custom events to the SSE client, which can be used for real-time updates or notifications.
        /// It constructs the event with a type, data, and an optional ID, and writes it to the response stream.
        /// The event type can be used to differentiate between different kinds of events on the client side.
        /// </summary>
        /// <param name="eventType">Event type name.</param>
        /// <param name="data">Event data string.</param>
        /// <param name="id">Optional event ID.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task SendSseEvent(string eventType, string data, string id = null)
        {
            if (!string.IsNullOrEmpty(id))
            {
                await WriteLine($"id: {id}").ConfigureAwait(false);
            }

            if (!string.IsNullOrEmpty(eventType))
            {
                await WriteLine($"event: {eventType}").ConfigureAwait(false);
            }

            await WriteLine($"data: {data}{PodeHelpers.NEW_LINE}", true).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a retry interval directive to the SSE client.
        /// This method is used to inform the client how long it should wait before attempting to reconnect after a disconnection.
        /// The retry interval is specified in milliseconds, and this directive helps manage the reconnection attempts in a controlled manner.
        /// </summary>
        /// <param name="retry">Retry interval in milliseconds.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task SendSseRetry(int retry)
        {
            if (retry <= 0)
            {
                return;
            }

            await WriteLine($"retry: {retry}", true).ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a raw signal string through the response stream.
        /// This method is typically used to send server signals or messages that do not require any specific formatting.
        /// It writes the signal value directly to the response stream, allowing for immediate communication with the client.
        /// </summary>
        /// <param name="signal">The signal object to send.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task SendSignal(PodeServerSignal signal)
        {
            if (!string.IsNullOrEmpty(signal.Value))
            {
                await Write(signal.Value).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Writes a string message to the response, either directly or over a WebSocket.
        /// This method checks if the context is a WebSocket connection and writes the message accordingly.
        /// If the context is not a WebSocket, it encodes the message to bytes and writes it directly to the response stream.
        /// </summary>
        /// <param name="message">Message to send.</param>
        /// <param name="flush">Whether to flush immediately after writing.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task Write(string message, bool flush = false)
        {
            // simple messages
            if (!Context.IsWebSocket)
            {
                await Write(Encoding.GetBytes(message), flush).ConfigureAwait(false);
            }

            // web socket message
            else
            {
                await WriteFrame(message, PodeWsOpCode.Text, flush).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Writes a WebSocket frame message to the response stream.
        /// This method handles the framing of the message according to the WebSocket protocol, including setting the FIN bit, operation code, and payload length.
        /// It supports both text and binary messages, and can handle large messages by splitting them into smaller frames.
        /// </summary>
        /// <param name="message">Message to send.</param>
        /// <param name="opCode">WebSocket operation code.</param>
        /// <param name="flush">Whether to flush immediately after writing.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task WriteFrame(string message, PodeWsOpCode opCode = PodeWsOpCode.Text, bool flush = false)
        {
            if (IsDisposed)
            {
                return;
            }

            var msgBytes = Encoding.GetBytes(message);
            var msgLength = msgBytes.Length;
            var offset = 0;
            var firstFrame = true;

            while (offset < msgLength || (msgLength == 0 && firstFrame))
            {
                var frameSize = Math.Min(msgLength - offset, MAX_FRAME_SIZE);
                var frame = new byte[frameSize];
                Array.Copy(msgBytes, offset, frame, 0, frameSize);

                // fin bit and op code
                var isFinal = offset + frameSize >= msgLength;
                var finBit = (byte)(isFinal ? 0x80 : 0x00);
                var opCodeByte = (byte)(firstFrame ? opCode : PodeWsOpCode.Continuation);

                // build the frame buffer
                var buffer = new List<byte> { (byte)(finBit | opCodeByte) };

                if (frameSize < 126)
                {
                    buffer.Add((byte)((byte)0x00 | (byte)frameSize));
                }
                else if (frameSize <= UInt16.MaxValue)
                {
                    buffer.Add((byte)((byte)0x00 | (byte)126));
                    buffer.Add((byte)((frameSize >> 8) & (byte)255));
                    buffer.Add((byte)(frameSize & (byte)255));
                }
                else
                {
                    buffer.Add((byte)((byte)0x00 | (byte)127));
                    buffer.Add((byte)((frameSize >> 56) & (byte)255));
                    buffer.Add((byte)((frameSize >> 48) & (byte)255));
                    buffer.Add((byte)((frameSize >> 40) & (byte)255));
                    buffer.Add((byte)((frameSize >> 32) & (byte)255));
                    buffer.Add((byte)((frameSize >> 24) & (byte)255));
                    buffer.Add((byte)((frameSize >> 16) & (byte)255));
                    buffer.Add((byte)((frameSize >> 8) & (byte)255));
                    buffer.Add((byte)(frameSize & (byte)255));
                }

                // add the payload
                buffer.AddRange(frame);

                // send
                await Write(buffer.ToArray(), flush).ConfigureAwait(false);
                offset += frameSize;
                firstFrame = false;
            }
        }

        /// <summary>
        /// Writes a line of text to the response, followed by a newline.
        /// This method encodes the message to bytes and writes it to the response stream.
        /// It is typically used for sending log messages or simple text responses.
        /// </summary>
        /// <param name="message">Message to send.</param>
        /// <param name="flush">Whether to flush immediately after writing.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task WriteLine(string message, bool flush = false)
        {
            await Write(Encoding.GetBytes($"{message}{PodeHelpers.NEW_LINE}"), flush).ConfigureAwait(false);
        }

        // write a byte array to the actual client stream
        /// <summary>
        /// Writes a byte array to the response stream.
        /// This method checks if the request input stream is writable before attempting to write.
        /// If the request is disposed or the input stream cannot be written to, it does nothing.
        /// </summary>
        /// <param name="buffer">Buffer of bytes to send.</param>
        /// <param name="flush">Whether to flush immediately after writing.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task Write(byte[] buffer, bool flush = false)
        {
            if (Request.IsDisposed || !Request.InputStream.CanWrite)
            {
                return;
            }

            try
            {
#if NETCOREAPP2_1_OR_GREATER
                await Request.InputStream.WriteAsync(buffer.AsMemory(), Context.Listener.CancellationToken).ConfigureAwait(false);
#else
                await Request.InputStream.WriteAsync(buffer, 0, buffer.Length, Context.Listener.CancellationToken).ConfigureAwait(false);
#endif

                if (flush)
                {
                    await Flush().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (AggregateException aex)
            {
                PodeHelpers.HandleAggregateException(aex, Context.Listener);
            }
            catch (Exception ex)
            {
                PodeHelpers.WriteException(ex, Context.Listener);
                throw;
            }
        }

        /// <summary>
        /// Writes a file from a given path to the response.
        /// This method checks if the file exists and if it is small enough to be buffered in memory.
        /// If the file is larger than the defined maximum size, it streams the file directly to the response.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task WriteFileAsync(string path)
        {
            await WriteFileAsync(new FileInfo(path)).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes a file to the response, buffering small files and streaming large files.
        /// This method checks if the file exists and is a valid FileInfo object.
        /// If the file is smaller than or equal to 64 MiB, it reads the file into a memory stream and writes it to the output stream.
        /// </summary>
        /// <param name="file">File system object representing the file.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task WriteFileAsync(FileSystemInfo file)
        {
            if (!(file is FileInfo fi) || !fi.Exists)
                throw new FileNotFoundException($"File not found: {file.FullName}");

            // If the file is small enough, keep the existing behaviour.
            if (fi.Length <= MAX_IN_MEMORY_FILE_SIZE)
            {
                ContentLength64 = fi.Length;
                using (var fs = fi.OpenRead())
                {
                    fs.CopyTo(OutputStream);   // original logic
                }
                return;
            }

            // Bigger than 2 GB – stream it
            await WriteLargeFile(fi).ConfigureAwait(false);
        }

        /// <summary>
        /// Synchronous façade for PowerShell callers that don’t use 'await'.
        /// Just forwards to <see cref="WriteFileAsync"/> and blocks.
        /// </summary>
        /// <param name="file">File system object representing the file.</param>
        public void WriteFile(FileSystemInfo file)
        {
            WriteFileAsync(file).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Synchronous façade for PowerShell callers that don’t use 'await'.
        /// Just forwards to <see cref="WriteFileAsync"/> and blocks.
        /// </summary>
        /// <param name="path">The file path.</param>
        public void WriteFile(string path)
        {
            WriteFileAsync(new FileInfo(path)).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Streams a large file (>64 MiB) directly to the client response.
        /// This method reads the file in chunks and writes it to the response stream.
        /// It is designed to handle large files efficiently without loading the entire file into memory.
        /// </summary>
        /// <param name="fileInfo">Information about the file to stream.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public async Task WriteLargeFile(FileInfo fileInfo)
        {
            if (IsDisposed)
            {
                return;
            }

            if (!fileInfo.Exists)
            {
                throw new FileNotFoundException($"File not found: {fileInfo.FullName}");
            }

            ContentLength64 = fileInfo.Length;
            await SendHeaders(false).ConfigureAwait(false);

            const int BufferSize = 64 * 1024;
            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

            try
            {
                using (var fs = fileInfo.OpenRead())
                {
                    int read;
#if NETCOREAPP2_1_OR_GREATER
                    while ((read = await fs
                                 .ReadAsync(buffer.AsMemory(0, BufferSize), Context.Listener.CancellationToken)
                                 .ConfigureAwait(false)) > 0)
                    {
                        await Request.InputStream
                            .WriteAsync(buffer.AsMemory(0, read), Context.Listener.CancellationToken)
                            .ConfigureAwait(false);

                        // Periodically flush to keep connection alive
                        await Request.InputStream
                            .FlushAsync(Context.Listener.CancellationToken)
                            .ConfigureAwait(false);
                    }
#else
            while ((read = await fs
                         .ReadAsync(buffer, 0, buffer.Length, Context.Listener.CancellationToken)
                         .ConfigureAwait(false)) > 0)
            {
                await Request.InputStream
                    .WriteAsync(buffer, 0, read, Context.Listener.CancellationToken)
                    .ConfigureAwait(false);

                await Request.InputStream
                    .FlushAsync(Context.Listener.CancellationToken)
                    .ConfigureAwait(false);
            }
#endif
                }

                SentBody = true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        /// <summary>
        /// Sets default headers for the HTTP response.
        /// This method ensures that the response has the necessary headers such as Content-Length, Date, Server, and X-Pode-ContextId.
        /// </summary>
        private void SetDefaultHeaders()
        {
            // ensure content length (remove for 1xx responses, ensure added otherwise)
            if (StatusCode < 200 || SseEnabled)
            {
                Headers.Remove("Content-Length");
            }
            else
            {
                if (ContentLength64 == 0)
                {
                    ContentLength64 = OutputStream.Length > 0 ? OutputStream.Length : 0;
                }
            }

            // set the date
            if (Headers.ContainsKey("Date"))
            {
                Headers.Remove("Date");
            }

            Headers.Add("Date", DateTime.UtcNow.ToString("r", CultureInfo.InvariantCulture));

            // set the server if allowed
            if (Context.Listener.ShowServerDetails)
            {
                if (!Headers.ContainsKey("Server"))
                {
                    Headers.Add("Server", "Pode");
                }
            }
            else
            {
                if (Headers.ContainsKey("Server"))
                {
                    Headers.Remove("Server");
                }
            }

            // set context/socket ID
            if (Headers.ContainsKey("X-Pode-ContextId"))
            {
                Headers.Remove("X-Pode-ContextId");
            }

            Headers.Add("X-Pode-ContextId", Context.ID);

            // close the connection, only if request didn't specify keep-alive
            if (!Context.IsKeepAlive && !Context.IsWebSocket && !SseEnabled)
            {
                if (Headers.ContainsKey("Connection"))
                {
                    Headers.Remove("Connection");
                }

                Headers.Add("Connection", "close");
            }
        }

        /// <summary>
        /// Builds the HTTP response headers as a string.
        /// This method constructs the response headers from the PodeResponseHeaders object,
        /// </summary>
        /// <param name="headers"></param>
        /// <returns></returns>
        private string BuildHeaders(PodeResponseHeaders headers)
        {
            var builder = new StringBuilder();
            builder.Append(HttpResponseLine);

            foreach (var key in headers.Keys)
            {
                foreach (var value in headers.Get(key))
                {
                    builder.Append($"{key}: {value}{PodeHelpers.NEW_LINE}");
                }
            }

            builder.Append(PodeHelpers.NEW_LINE);
            return builder.ToString();
        }

        /// <summary>
        /// Disposes the response object and releases its resources.
        /// This method is called to clean up the response when it is no longer needed.
        /// It ensures that any managed resources, such as the output stream, are properly disposed of.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes managed and optionally unmanaged resources.
        /// This method is called by the Dispose method and can be overridden in derived classes to release additional resources.
        /// It checks if the object has already been disposed to avoid multiple disposals.
        /// </summary>
        /// <param name="disposing">Whether managed resources should be disposed.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (IsDisposed)
                return;

            if (disposing)
            {
                // free managed resources
                if (OutputStream != null)
                {
                    OutputStream.Dispose();
                    OutputStream = null;
                }
            }

            // no unmanaged resources to free

            PodeHelpers.WriteErrorMessage($"Response disposed", Context.Listener, PodeLoggingLevel.Verbose, Context);
            IsDisposed = true;
        }

    }
}