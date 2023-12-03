using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Blog.Core.Common.Helper;
using Aspire.Idp.Models;
using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using static IdentityModel.OidcConstants;

namespace Aspire.Idp.Controllers.Client
{
    [Route("[controller]/[action]")]
    public class ClientsManagerController : Controller
    {
        private readonly ConfigurationDbContext _configurationDbContext;

        public ClientsManagerController(ConfigurationDbContext configurationDbContext)
        {
            _configurationDbContext = configurationDbContext;
        }

        /// <summary>
        /// 客户端页
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Index(int page, int rows)
        {
            try
            {
                if (page < 1 || rows < 1)
                {
                    return View();
                }
                var res = await _configurationDbContext.Clients
                .Include(d => d.AllowedGrantTypes)
                .Include(d => d.AllowedScopes)
                .Include(d => d.AllowedCorsOrigins)
                .Include(d => d.RedirectUris)
                .Include(d => d.PostLogoutRedirectUris)
                .Skip((page - 1) * rows).Take(rows)
                .Select(i => new ClientDto
                {
                    ClientId = i.ClientId,
                    AllowAccessTokensViaBrowser = i.AllowAccessTokensViaBrowser.ToString(),
                    AllowedCorsOrigins = JsonConvert.SerializeObject(i.AllowedCorsOrigins),
                    AllowedGrantTypes = JsonConvert.SerializeObject(i.AllowedGrantTypes),
                    AllowedScopes = JsonConvert.SerializeObject(i.AllowedScopes),
                    ClientName = i.ClientName,
                    ClientSecrets = JsonConvert.SerializeObject(i.ClientSecrets),
                    Description = i.Description,
                    Id = i.Id,
                    PostLogoutRedirectUris = JsonConvert.SerializeObject(i.PostLogoutRedirectUris),
                    RedirectUris = JsonConvert.SerializeObject(i.RedirectUris),
                })
                .ToListAsync();


                return Json(new MessageModel()
                {
                    success = true,
                    msg = "获取成功",
                    response = new
                    {
                        data = res,
                        total = await _configurationDbContext.Clients.CountAsync(),
                    }
                });

            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }

        /// <summary>
        /// 客户端操作页
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> CreateOrEdit(int id)
        {
            var clientDto = new ClientDto();
           
            // 如果是编辑
            if (id > 0)
            {
                var model = (await _configurationDbContext.Clients
                .Include(d => d.AllowedGrantTypes)
                .Include(d => d.AllowedScopes)
                .Include(d => d.AllowedCorsOrigins)
                .Include(d => d.RedirectUris)
                .Include(d => d.PostLogoutRedirectUris)
                .Include(d => d.ClientSecrets)
                .FirstOrDefaultAsync(d => d.Id == id));

                if (model != null)
                {
                    clientDto = new ClientDto()
                    {
                        Id = id,
                        ClientId = model.ClientId,
                        ClientName = model.ClientName,
                        Description = model.Description,
                        AllowAccessTokensViaBrowser = (model.AllowAccessTokensViaBrowser).ObjToString(),
                        AllowedCorsOrigins = string.Join(",", model.AllowedCorsOrigins.Select(i => i.Origin)),
                        AllowedGrantTypes = string.Join(",", model.AllowedGrantTypes.Select(i => i.GrantType)),
                        AllowedScopes = string.Join(",", model.AllowedScopes.Select(i => i.Scope)),
                        PostLogoutRedirectUris = string.Join(",", model.PostLogoutRedirectUris.Select(i => i.PostLogoutRedirectUri)),
                        RedirectUris = string.Join(",", model.RedirectUris.Select(i => i.RedirectUri)),
                        ClientSecrets = string.Join(",", model.ClientSecrets.Select(d => d.Value)),
                    };
                    ViewData["title"] = "编辑客户端";
                }
            }
            else
            {
                ViewData["title"] = "添加客户端";
            }
            return View(clientDto);
        }



        /// <summary>
        /// 保存客户端
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Save([FromBody] ClientDto request)
        {
            if (request == null)
            {
                return BadRequest();
            }
            if (request.Id == 0)
            {
                IdentityServer4.Models.Client client = new IdentityServer4.Models.Client()
                {
                    ClientId = request?.ClientId,
                    ClientName = request?.ClientName,
                    Description = request?.Description,
                    AllowAccessTokensViaBrowser = (request?.AllowAccessTokensViaBrowser).ObjToBool(),
                    AllowedCorsOrigins = request?.AllowedCorsOrigins?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                    AllowedGrantTypes = request?.AllowedGrantTypes?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                    AllowedScopes = request?.AllowedScopes?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                    PostLogoutRedirectUris = request?.PostLogoutRedirectUris?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                    RedirectUris = request?.RedirectUris?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                };

                if (!string.IsNullOrEmpty(request.ClientSecrets))
                {
                    client.ClientSecrets = new List<Secret>() { new Secret(request.ClientSecrets.Sha256()) };
                }

                var result = (await _configurationDbContext.Clients.AddAsync(client.ToEntity()));
                await _configurationDbContext.SaveChangesAsync();

            }
            else if (request.Id > 0)
            {
                var modelEF = (await _configurationDbContext.Clients
                .Include(d => d.AllowedGrantTypes)
                .Include(d => d.AllowedScopes)
                .Include(d => d.AllowedCorsOrigins)
                .Include(d => d.RedirectUris)
                .Include(d => d.PostLogoutRedirectUris)
                .ToListAsync()).FirstOrDefault(d => d.Id == request.Id);


                modelEF.ClientId = request?.ClientId;
                modelEF.ClientName = request?.ClientName;
                modelEF.Description = request?.Description;
                modelEF.AllowAccessTokensViaBrowser = (request?.AllowAccessTokensViaBrowser).ObjToBool();

                var AllowedCorsOrigins = new List<IdentityServer4.EntityFramework.Entities.ClientCorsOrigin>();
                if (!string.IsNullOrEmpty(request?.AllowedCorsOrigins))
                {
                    request?.AllowedCorsOrigins.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        AllowedCorsOrigins.Add(new IdentityServer4.EntityFramework.Entities.ClientCorsOrigin()
                        {
                            Client = modelEF,
                            ClientId = modelEF.Id,
                            Origin = s
                        });
                    });
                    modelEF.AllowedCorsOrigins = AllowedCorsOrigins;
                }



                var AllowedGrantTypes = new List<IdentityServer4.EntityFramework.Entities.ClientGrantType>();
                if (!string.IsNullOrEmpty(request?.AllowedGrantTypes))
                {
                    request?.AllowedGrantTypes.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        AllowedGrantTypes.Add(new IdentityServer4.EntityFramework.Entities.ClientGrantType()
                        {
                            Client = modelEF,
                            ClientId = modelEF.Id,
                            GrantType = s
                        });
                    });
                    modelEF.AllowedGrantTypes = AllowedGrantTypes;
                }



                var AllowedScopes = new List<IdentityServer4.EntityFramework.Entities.ClientScope>();
                if (!string.IsNullOrEmpty(request?.AllowedScopes))
                {
                    request?.AllowedScopes.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        AllowedScopes.Add(new IdentityServer4.EntityFramework.Entities.ClientScope()
                        {
                            Client = modelEF,
                            ClientId = modelEF.Id,
                            Scope = s
                        });
                    });
                    modelEF.AllowedScopes = AllowedScopes;
                }


                var PostLogoutRedirectUris = new List<IdentityServer4.EntityFramework.Entities.ClientPostLogoutRedirectUri>();
                if (!string.IsNullOrEmpty(request?.PostLogoutRedirectUris))
                {
                    request?.PostLogoutRedirectUris.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        PostLogoutRedirectUris.Add(new IdentityServer4.EntityFramework.Entities.ClientPostLogoutRedirectUri()
                        {
                            Client = modelEF,
                            ClientId = modelEF.Id,
                            PostLogoutRedirectUri = s
                        });
                    });
                    modelEF.PostLogoutRedirectUris = PostLogoutRedirectUris;
                }


                var RedirectUris = new List<IdentityServer4.EntityFramework.Entities.ClientRedirectUri>();
                if (!string.IsNullOrEmpty(request?.RedirectUris))
                {
                    request?.RedirectUris.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        RedirectUris.Add(new IdentityServer4.EntityFramework.Entities.ClientRedirectUri()
                        {
                            Client = modelEF,
                            ClientId = modelEF.Id,
                            RedirectUri = s
                        });
                    });
                    modelEF.RedirectUris = RedirectUris;
                }

                var result = (_configurationDbContext.Clients.Update(modelEF));
                await _configurationDbContext.SaveChangesAsync();
            }

            return Ok(Url.Action(nameof(Index)));
        }


        /// <summary>
        /// 删除客户端
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Delete(int id) {

            try
            {
                var res =  await _configurationDbContext.Clients.FirstOrDefaultAsync(i => i.Id == id);
                _configurationDbContext.Clients.Remove(res);
                await _configurationDbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
            return Ok();
            
        }

    }
}