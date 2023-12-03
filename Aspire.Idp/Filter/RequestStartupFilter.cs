using Aspire.Idp.Middleware;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using System;

namespace Aspire.Idp.Filter
{
    /// <summary>
    /// 启动之前的过滤器,在所有中间件之前
    /// </summary>
    public class RequestStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {

            return builder =>
            {
                builder.UseMiddleware<RequestMiddleware>();
                next(builder);
            };
        }
    }
}
