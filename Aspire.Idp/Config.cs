// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Aspire.Idp.Extensions;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Linq;

namespace Aspire.Idp
{
    public class Config
    {
        // scopes define the resources in your system
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource("roles", "角色", new List<string> { JwtClaimTypes.Role }),
                new IdentityResource("role_name", "角色名", new List<string> { "role_name" }),
            };
        }

        // v4更新
        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new ApiScope[] {
                 new ApiScope("Aspire.Idp.api"),
                 new ApiScope("Aspire.Idp.api.Module"),
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            // Aspire.Idp 项目
            return new List<ApiResource> {
                new ApiResource("Aspire.Idp.api", "Aspire.Idp API") {
                    // include the following using claims in access token (in addition to subject id)
                    //requires using using IdentityModel;
                    UserClaims = { JwtClaimTypes.Name, JwtClaimTypes.Role,"role_name" },
                    
                    // v4更新
                    Scopes={ "Aspire.Idp.api","Aspire.Idp.api.Module"},

                    ApiSecrets = new List<Secret>()
                    {
                        new Secret("api_secret".Sha256())
                    },
                }
            };
        }

        // clients want to access resources (aka scopes)
        public static IEnumerable<Client> GetClients()
        {
            // client
            return new List<Client> {
                // 1、blog.vue 前端vue项目
                new Client {
                    ClientId = "blogvuejs",
                    ClientName = "Blog.Vue JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,
                    RequireConsent = true,
                    RedirectUris =           {
                        "http://vueblog.neters.club/callback",
                        "http://apk.neters.club/oauth2-redirect.html",

                        "http://localhost:6688/callback",
                        "http://localhost:8081/oauth2-redirect.html",
                    },
                    PostLogoutRedirectUris = { "http://vueblog.neters.club","http://localhost:6688" },
                    AllowedCorsOrigins =     { "http://vueblog.neters.club","http://localhost:6688" },

                    AccessTokenLifetime=3600,

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "roles",
                        "Aspire.Idp.api.BlogModule"
                    }
                },
                // 2、blog.admin 前端vue项目
                new Client {
                    ClientId = "blogadminjs",
                    ClientName = "Blog.Admin JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,

                    RedirectUris =
                    {
                        "http://vueadmin.neters.club/callback",
                        "http://apk.neters.club/oauth2-redirect.html",

                        "http://localhost:2364/callback",
                        "http://localhost:8081/oauth2-redirect.html",
                    },
                    PostLogoutRedirectUris = { "http://vueadmin.neters.club","http://localhost:2364" },
                    AllowedCorsOrigins =     { "http://vueadmin.neters.club","http://localhost:2364"  },

                    AccessTokenLifetime=3600,

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "roles",
                        "Aspire.Idp.api"
                    }
                },
                // 3、nuxt.tbug 前端nuxt项目
                new Client {
                    ClientId = "tibugnuxtjs",
                    ClientName = "Nuxt.tBug JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowAccessTokensViaBrowser = true,

                    RedirectUris =           { "http://tibug.neters.club/callback" },
                    PostLogoutRedirectUris = { "http://tibug.neters.club" },
                    AllowedCorsOrigins =     { "http://tibug.neters.club" },

                    AccessTokenLifetime=3600,

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "roles",
                        "Aspire.Idp.api"
                    }
                },
                // 4、DDD 后端MVC项目
                new Client
                {
                    ClientId = "chrisdddmvc",
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    RequireConsent = false,
                    RequirePkce = true,
                    AlwaysIncludeUserClaimsInIdToken=true,//将用户所有的claims包含在IdToken内
                
                    // where to redirect to after login
                    RedirectUris = { "http://ddd.neters.club/signin-oidc" },

                    // where to redirect to after logout
                    PostLogoutRedirectUris = { "http://ddd.neters.club/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "roles",
                        "role_name",
                    }
                },
                // 5、控制台客户端
                new Client
                {
                    ClientId = "Console",
                    ClientSecrets = { new Secret("secret".Sha256()) },

                     AllowOfflineAccess = true,//如果要获取refresh_tokens ,必须把AllowOfflineAccess设置为true
                    AllowedGrantTypes = new List<string>()
                    {
                        GrantTypes.ResourceOwnerPassword.FirstOrDefault(),
                        GrantTypes.ClientCredentials.FirstOrDefault(),
                        GrantTypeCustom.ResourceWeixinOpen,
                    },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "offline_access",
                        "Aspire.Idp.api"
                    }
                },
                // 6、mvp 后端blazor.server项目
                new Client
                {
                    ClientId = "blazorserver",
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    RequireConsent = false,
                    RequirePkce = true,
                    AlwaysIncludeUserClaimsInIdToken=true,//将用户所有的claims包含在IdToken内
                    AllowAccessTokensViaBrowser = true,
                
                    // where to redirect to after login
                    RedirectUris = { "https://mvp.neters.club/signin-oidc" },

                    AllowedCorsOrigins =     { "https://mvp.neters.club" },
                   
                    // where to redirect to after logout
                    PostLogoutRedirectUris = { "https://mvp.neters.club/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "roles",
                        "role_name",
                        "Aspire.Idp.api"
                    }
                },

                // 7、测试 hybrid 模式
                new Client
                {
                    ClientId = "hybridclent",
                    ClientName="Demo MVC Client",
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Hybrid,
                 
                    RequirePkce = false,

                    RedirectUris = { "http://localhost:1003/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:1003/signout-callback-oidc" },

                    AllowOfflineAccess=true,
                    AlwaysIncludeUserClaimsInIdToken=true,

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "roles",
                        "role_name",
                        "Aspire.Idp.api"
                    }
                }
            };
        }
    }
} 