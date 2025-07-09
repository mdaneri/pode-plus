using System;
using System.Net;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http.Features;
#endif
namespace Pode
{
    public class PodeKestrelListener : PodeListener
    {
#if NET8_0_OR_GREATER
        public const string Name = "PodeKestrelListener";
        public bool IsListening { get; private set; }
        private IList<PodeSocket> Sockets;

        public int ContextsCount
        {
            get => Contexts.Count;
        }

        private WebHostBuilder WebBuilder;
        private IWebHost WebHost;





        public PodeKestrelListener(CancellationToken cancellationToken)
            : base(cancellationToken)
        {

            WebBuilder = new WebHostBuilder();

            WebBuilder.ConfigureServices(services =>
            {
                services.AddRouting();
                services.Configure<FormOptions>(options =>
                {
                    options.MultipartBodyLengthLimit = this.RequestBodySize;
                });
            });

            WebBuilder.Configure(app =>
            {
                var routeHandler = new RouteHandler(ctx =>
                {
                    var _podeContext = new PodeContext(ctx, this);
                    this.AddContext(_podeContext);
                    return _podeContext.Start();
                });

                var routeBuilder = new RouteBuilder(app, routeHandler);
                routeBuilder.MapRoute("pode sub-routes", "{*.}");

                var routes = routeBuilder.Build();
                app.UseRouter(routes);
            });

            Sockets = new List<PodeSocket>();
           Contexts = new PodeItemQueue<PodeContext>();
        }



        public override void Start()
        {
            WebBuilder.UseKestrel((options) =>
            {
                foreach (var socket in Sockets)
                {
                    socket.Listen(options);
                }

                options.Limits.MaxRequestBodySize = this.RequestBodySize;
            });

            WebHost = WebBuilder.Build();
            WebHost.RunAsync(CancellationToken);
            IsListening = true;
        }

        public PodeSocket FindSocket(IPEndPoint ipEndpoint)
        {
            return Sockets.FirstOrDefault(x => x.Equals(ipEndpoint));
        }

        public void Dispose()
        {
            IsListening = false;
            WebHost.Dispose();
            base.Dispose();
        }
#endif
    }
}