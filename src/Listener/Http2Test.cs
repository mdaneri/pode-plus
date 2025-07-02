using System;
using System.Reflection;

namespace Pode.Test
{
    public static class Http2Test
    {
        public static void TestHttp2Support()
        {
            Console.WriteLine($"Target Framework: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");

#if NETSTANDARD2_0
            Console.WriteLine("Compiled with NETSTANDARD2_0 - HTTP/2 support disabled");

            // Test that HTTP/2 types are not available
            var assembly = Assembly.GetExecutingAssembly();
            var http2RequestType = assembly.GetType("Pode.PodeHttp2Request");
            var http2ResponseType = assembly.GetType("Pode.PodeHttp2Response");

            Console.WriteLine($"PodeHttp2Request available: {http2RequestType != null}");
            Console.WriteLine($"PodeHttp2Response available: {http2ResponseType != null}");
#else
            Console.WriteLine("Compiled with .NET Core/5+ - HTTP/2 support enabled");

            // Test that HTTP/2 types are available
            var assembly = Assembly.GetExecutingAssembly();
            var http2RequestType = assembly.GetType("Pode.PodeHttp2Request");
            var http2ResponseType = assembly.GetType("Pode.PodeHttp2Response");

            Console.WriteLine($"PodeHttp2Request available: {http2RequestType != null}");
            Console.WriteLine($"PodeHttp2Response available: {http2ResponseType != null}");
#endif
        }
    }
}
