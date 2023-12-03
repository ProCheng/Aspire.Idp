using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Reflection;
using System.Threading.RateLimiting;
using Aspire.Idp;
using Aspire.Idp.Authorization;
using Aspire.Idp.CfgModel;
using Aspire.Idp.Data;
using Aspire.Idp.Extensions;
using Aspire.Idp.Filter;
using Aspire.Idp.Models;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;


namespace Aspire.Idp
{
    public class Program
    {

        public static void Main(string[] args)
        {
            Console.Title = "Idp Ef Asp.Identity";

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.File(@"Logs/identityserver4_log.txt")
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Literate)
                .CreateLogger();

            var seed = args.Contains("/seed");
            if (seed)
            {
                args = args.Except(new[] { "/seed" }).ToArray();
            }


            var builder = WebApplication.CreateBuilder(args);

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.AllowSynchronousIO = true;//启用同步 IO
            })
            //.UseUrls("http://*:5004")
            .ConfigureLogging((hostingContext, builder) =>
            {
                builder.ClearProviders();
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                builder.AddConsole();
                builder.AddDebug();
            });


            // 注入服务
            var app = ConfigServices(builder);

            // http管道
            ConfigPipeline(app);    
           
            if (seed)
            {
                SeedData.EnsureSeedData(app.Services);
            }

            app.Run();
        }


         



        public static WebApplication ConfigServices(WebApplicationBuilder builders) {


            var services = builders.Services;
            // services.AddTransient<IStartupFilter, RequestStartupFilter>();  // 学习


            services.AddResponseCaching();      // 添加响应缓存中间件
            services.AddResponseCompression(options =>      // 添加响应压缩服务
            {
                options.EnableForHttps = true;
                //options.Providers.Add<BrotliCompressionProvider>();
                options.Providers.Add<GzipCompressionProvider>();
                //options.MimeTypes =
                //   ResponseCompressionDefaults.MimeTypes.Concat(
                //       new[] { "image/png" });
            });


            services.AddSameSiteCookiePolicy();

            string connectionStringFile = builders.Configuration.GetConnectionString("DefaultConnection_file");
            var connectionString = File.Exists(connectionStringFile) ? File.ReadAllText(connectionStringFile).Trim() : builders.Configuration.GetConnectionString("DefaultConnection");
            var isMysql = builders.Configuration.GetConnectionString("IsMysql").ObjToBool();

            if (connectionString == "")
            {
                throw new Exception("数据库配置异常");
            }
            var migrationsAssembly = Assembly.GetExecutingAssembly().GetName().Name;

            if (isMysql)
            {
                // mysql
                services.AddDbContext<ApplicationDbContext>(options => options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 24))));
            }
            else
            {
                // sqlserver
                services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));
            };


            services.Configure<IdentityOptions>(
              options =>
              {
                  //options.Password.RequireDigit = false;
                  //options.Password.RequireLowercase = false;
                  //options.Password.RequireNonAlphanumeric = false;
                  //options.Password.RequireUppercase = false;
                  //options.SignIn.RequireConfirmedEmail = false;
                  //options.SignIn.RequireConfirmedPhoneNumber = false;
                  //options.User.AllowedUserNameCharacters = null;
              });

            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.User = new UserOptions
                {
                    RequireUniqueEmail = true, //要求Email唯一
                    AllowedUserNameCharacters = null //允许的用户名字符
                };
                options.Password = new PasswordOptions
                {
                    RequiredLength = 8, //要求密码最小长度，默认是 6 个字符
                    RequireDigit = true, //要求有数字
                    RequiredUniqueChars = 3, //要求至少要出现的字母数
                    RequireLowercase = true, //要求小写字母
                    RequireNonAlphanumeric = false, //要求特殊字符
                    RequireUppercase = false //要求大写字母
                };

                //options.Lockout = new LockoutOptions
                //{
                //    AllowedForNewUsers = true, // 新用户锁定账户
                //    DefaultLockoutTimeSpan = TimeSpan.FromHours(1), //锁定时长，默认是 5 分钟
                //    MaxFailedAccessAttempts = 3 //登录错误最大尝试次数，默认 5 次
                //};
                //options.SignIn = new SignInOptions
                //{
                //    RequireConfirmedEmail = true, //要求激活邮箱
                //    RequireConfirmedPhoneNumber = true //要求激活手机号
                //};
                //options.ClaimsIdentity = new ClaimsIdentityOptions
                //{
                //    // 这里都是修改相应的Cliams声明的
                //    RoleClaimType = "IdentityRole",
                //    UserIdClaimType = "IdentityId",
                //    SecurityStampClaimType = "SecurityStamp",
                //    UserNameClaimType = "IdentityName"
                //};
            })
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = new PathString("/Oauth2/Authorize");
            });


            //配置session的有效时间,单位秒
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromSeconds(30);
            });

            services.AddControllersWithViews().AddJsonOptions(i => {

                i.JsonSerializerOptions.Converters.Add(
                    new UtilConvert.DateTimeConverter("yyyy-MM-dd HH:mm:ss")
                    );
                i.JsonSerializerOptions.PropertyNamingPolicy = null;
            });

            services.Configure<IISOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = false;
            });

            //services.Configure<ForwardedHeadersOptions>(options =>
            //{
            //    options.ForwardedHeaders =
            //        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            //    options.KnownNetworks.Clear();
            //    options.KnownProxies.Clear();
            //});

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                // 查看发现文档
                if (builders.Configuration["StartUp:IsOnline"].ObjToBool())
                {
                    options.IssuerUri = builders.Configuration["StartUp:OnlinePath"].ObjToString();
                }
                options.UserInteraction = new IdentityServer4.Configuration.UserInteractionOptions
                {
                    LoginUrl = "/Oauth2/Authorize",//登录地址  
                };
            })

                // 自定义验证，可以不走Identity
                //.AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .AddExtensionGrantValidator<WeiXinOpenGrantValidator>()

                // 数据库模式
                .AddAspNetIdentity<ApplicationUser>()

                // this adds the config data from DB (clients, resources)
                .AddConfigurationStore(options =>
                {
                    if (isMysql)
                    {
                        options.ConfigureDbContext = b => b.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 24)), sql => sql.MigrationsAssembly(migrationsAssembly));
                    }
                    else
                    {
                        options.ConfigureDbContext = b => b.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationsAssembly));
                    }
                })
                // this adds the operational data from DB (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    if (isMysql)
                    {
                        options.ConfigureDbContext = b => b.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 24)), sql => sql.MigrationsAssembly(migrationsAssembly));
                    }
                    else
                    {
                        options.ConfigureDbContext = b => b.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationsAssembly));
                    }

                    // 这将启用自动令牌清除。这是可选的。
                    options.EnableTokenCleanup = true;
                    // TokenCleanupInterval = 15    //选项 清除过时授权的频率(秒)。15在调试期间很有用
                });

            // 这里用测试的签名证书
            if (builders.Environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }


            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.Requirements.Add(new ClaimRequirement("role_name", "Admin")));
                options.AddPolicy("SuperAdmin", policy => policy.Requirements.Add(new ClaimRequirement("role_name", "SuperAdmin")));
            });

            services.AddSingleton<IAuthorizationHandler, ClaimsRequirementHandler>();

            // services.AddIpPolicyRateLimitSetup(Configuration);



            #region 速率服务

            var myRateLimitOptions = new MyRateLimitOptions();
            builders.Configuration.GetSection(MyRateLimitOptions.Cfg).Bind(myRateLimitOptions);


            services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = myRateLimitOptions.QuotaExceededResponse.StatusCode;  // 请求数量太多

                // 错误请求如何处理
                options.OnRejected = async (context, token) =>
                {


                    if (context.HttpContext.Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        context.HttpContext.Response.ContentType = "application/json";
                        await context.HttpContext.Response.WriteAsync(myRateLimitOptions.QuotaExceededResponse.ContentJson, token);
                    }
                    else
                    {
                        context.HttpContext.Response.ContentType = "text/html; charset=utf-8";
                        await context.HttpContext.Response.WriteAsync(myRateLimitOptions.QuotaExceededResponse.ContentHtml, token);
                    }


                };
                // 添加全局的
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>


                    RateLimitPartition.GetSlidingWindowLimiter(
                        httpContext.User.Identity?.Name ?? httpContext.Connection.RemoteIpAddress?.ToString(),
                        factory: partition => new SlidingWindowRateLimiterOptions
                        {
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            PermitLimit = myRateLimitOptions.PermitLimit,
                            QueueLimit = myRateLimitOptions.QueueLimit,
                            Window = TimeSpan.FromSeconds(myRateLimitOptions.Window),
                            SegmentsPerWindow = myRateLimitOptions.SegmentsPerWindow,
                            AutoReplenishment = myRateLimitOptions.AutoReplenishment,
                        }));


                // 自定义策略的
                //options.AddFixedWindowLimiter(policyName: "fixed", options =>
                //{
                //    options.PermitLimit = 4;
                //    options.Window = TimeSpan.FromSeconds(12);
                //    options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                //    options.QueueLimit = 2;
                //});
        });
            #endregion

            return builders.Build();
        }




        public static WebApplication ConfigPipeline(WebApplication app)
        {
            
            app.Use(async (ctx, next) =>
            {
                if (app.Configuration["StartUp:IsOnline"].ObjToBool())
                {
                    ctx.SetIdentityServerOrigin(app.Configuration["StartUp:OnlinePath"].ObjToString());
                }
                await next();
            });

            // app.UseIpLimitMildd();

            //app.UseForwardedHeaders();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }
            // app.UseHttpsRedirection();

            app.UseResponseCaching();    // 响应缓存中间件
            app.UseResponseCompression();   // 添加响应压缩中间件

            app.UseStaticFiles();
            app.UseCookiePolicy();


            app.UseRouting();
            app.UseRateLimiter();       // 放路由后面可以针对某一个api进行限速


            app.UseIdentityServer();


            app.UseAuthentication();
            app.UseAuthorization();



            app.UseSession();

            app.MapDefaultControllerRoute();


            return app;
        }

    }
}
