using Microsoft.AspNetCore.Http;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Aspire.Idp.Middleware
{
    public class RequestMiddleware
    {
        private readonly RequestDelegate _next;

        public RequestMiddleware(RequestDelegate next)
        {
            this._next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            //var option = httpContext.Request.Query["option"];

            //if (!string.IsNullOrWhiteSpace(option))
            //{
            //    httpContext.Items["option"] = WebUtility.HtmlEncode(option);
            //}

            Console.WriteLine("來了一个请求");
            await _next(httpContext);
        }
    }
}
