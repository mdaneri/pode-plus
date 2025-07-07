using System;
using System.Collections;
using System.IO;

namespace Pode
{
    /// <summary>
    /// Represents an HTTP/2 stream (RFC 7540 §5.1).
    /// An HTTP/2 stream is a bidirectional flow of bytes within an established connection,
    /// identified by a unique StreamId.
    /// Each stream can carry a sequence of frames, which are the fundamental units of communication in HTTP
    /// </summary>
    public class Http2Stream
    {
        /// <summary>
        /// Unique identifier for the stream (RFC 7540 §5.1).
        /// This is used to identify the stream within the HTTP/2 connection.
        /// The StreamId is a 31-bit integer, with 0 reserved for the connection-level stream.
        /// Each stream has a unique StreamId, which is used to differentiate it from
        /// other streams in the same connection.
        /// The StreamId is used in various HTTP/2 frames to indicate which stream the frame
        /// belongs to, such as HEADERS, DATA, and RST_STREAM frames.
        /// The StreamId is also used to manage flow control and prioritization of streams.
        /// The StreamId is assigned by the client or server when the stream is created.
        /// It is incremented by 2 for each new stream created, ensuring that odd StreamIds are used for client-initiated streams and even StreamIds for server-initiated streams.
        /// The StreamId is a key part of the HTTP/2 protocol, allowing multiple streams
        /// to be multiplexed over a single TCP connection.
        /// The StreamId is used to identify the stream in various HTTP/2 frames, such as HEADERS, DATA, and RST_STREAM frames.
        /// It is also used to manage flow control and prioritization of streams.
        /// The StreamId is a 31-bit integer,
        /// with 0 reserved for the connection-level stream.
        /// Each stream has a unique StreamId, which is used to differentiate it from other streams
        /// in the same connection.
        /// </summary>
        public int StreamId { get; }
        public Hashtable Headers { get; }
        /// <summary>
        /// Indicates if the stream has been reset (RFC 7540 §6.4).
        /// </summary>
        public bool Reset { get; set; }
        /// <summary>
        /// Error code for the stream, if reset (RFC 7540 §6.4).
        /// This is used to indicate the reason for the stream reset.
        /// If the stream has not been reset, this will be 0.
        /// If the stream has been reset, this will contain the error code. 0.
        /// </summary>
        public int ErrorCode { get; set; }

        /// <summary>
        /// Stream data, if any (RFC 7540 §6.1).
        /// This is used to hold the body data for the stream.
        /// If the stream has no body, this will be null.
        /// The data is stored in a MemoryStream for efficient access.
        /// If the stream has a body, this MemoryStream will contain the data.
        /// If the stream has no body, this will be an empty MemoryStream.
        /// This property is used to hold the body data for the stream.
        /// It is initialized as an empty MemoryStream and can be used to read/write data.
        /// If the stream has no body, this will be an empty MemoryStream.
        /// If the stream has a body, this MemoryStream will contain the data.
        /// </summary>
        public MemoryStream Data { get; set; }

        /// <summary>Flow-control window for this stream (RFC 7540 §6.9.2).</summary>
        public int WindowSize { get; private set; }

        /// <summary>Stream this one depends on (0 = root, RFC 7540 §5.3).</summary>
        public uint Dependency { get; set; }

        /// <summary>Weight expressed as 1-256 (RFC 7540 §5.3). Default 16.</summary>
        public byte Weight { get; set; }


        /// <summary>Create a new HTTP/2 stream with the correct initial window.</summary>
        public Http2Stream(int streamId, int initialWindowSize,
                           uint dependency = 0, byte weight = 16)
        {
            StreamId = streamId;
            WindowSize = initialWindowSize;   // 65 535 by default
            Dependency = dependency;
            Weight = weight;
            Data = new MemoryStream();
            Headers = new Hashtable(StringComparer.InvariantCultureIgnoreCase);
        }

        /// <summary>Increase the window (WINDOW_UPDATE handler).</summary>
        public void AddWindow(int delta) => WindowSize += delta;
    }
}