using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Aspire.Idp.Models;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;


namespace Aspire.Idp.Controllers.ApiResource
{
    [Route("[controller]/[action]")]

    public class ApiResourcesManagerController : Controller
    {
        private readonly ConfigurationDbContext _configurationDbContext;

        public ApiResourcesManagerController(ConfigurationDbContext configurationDbContext)
        {
            _configurationDbContext = configurationDbContext;
        }

        /// <summary>
        /// 资源api数据页
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Index(int page,int rows)
        {

            try
            {
                if (page < 1 || rows < 1)
                {
                    return View();
                }
                var res = await _configurationDbContext.ApiResources
               .Include(d => d.UserClaims)
               .Include(d => d.Scopes)
               .Skip((page - 1) * rows).Take(rows)
               .Select(i=> new ApiResourceDto() {
                    Id = i.Id,
                    Name = i.Name,
                    DisplayName = i.DisplayName,
                    Scopes = JsonConvert.SerializeObject(i.Scopes),
                     Description = i.Description,
                      UserClaims = JsonConvert.SerializeObject(i.UserClaims)
               })
               .ToListAsync();

                return Json(new MessageModel() {
                    success = true,
                    msg = "获取成功",
                    response = new
                    {
                        data = res,
                        total = await _configurationDbContext.ApiResources.CountAsync(),
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }

        }


        /// <summary>
        /// 资源api操作页
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpGet]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> CreateOrEdit(int id)
        {
            var apiResourceDto = new ApiResourceDto();

            // 如果是编辑
            if (id > 0)
            {
                var model = (await _configurationDbContext.ApiResources
                  .Include(d => d.UserClaims)
                  .Include(d => d.Scopes)
                  .FirstOrDefaultAsync(d => d.Id == id));

                if (model != null)
                {
                    apiResourceDto = new ApiResourceDto()
                    {
                        Id = id,
                        Name = model.Name,
                        DisplayName = model.DisplayName,
                        Description = model.Description,
                        UserClaims = string.Join(",", model?.UserClaims.Select(i => i.Type)),
                        Scopes = string.Join(",", model?.Scopes.Select(i => i.Scope)),
                    };
                    ViewData["title"] = "编辑资源api";
                }
            }
            else
            {
                ViewData["title"] = "添加资源api";
            }
            return View(apiResourceDto);



        }



        /// <summary>
        /// 保存资源api
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Save(ApiResourceDto request)
        {
            if (request == null)
            {
                return BadRequest();
            }

            // 新增
            if (request.Id == 0)
            {
                IdentityServer4.Models.ApiResource apiResource = new IdentityServer4.Models.ApiResource()
                {
                    Name = request.Name,
                    DisplayName = request.DisplayName,
                    Description = request.Description,
                    Enabled = true,
                    UserClaims = request.UserClaims?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                    Scopes = request.Scopes?.Split(",", StringSplitOptions.RemoveEmptyEntries),
                };
                var result = (await _configurationDbContext.ApiResources.AddAsync(apiResource.ToEntity()));
                await _configurationDbContext.SaveChangesAsync();


            }else if (request.Id > 0)
            {
                var modelEF = (await _configurationDbContext.ApiResources
                    .Include(d => d.UserClaims)
                    .Include(d => d.Scopes)
                    .ToListAsync()).FirstOrDefault(d => d.Id == request.Id);

                modelEF.Name = request.Name;
                modelEF.DisplayName = request.DisplayName;
                modelEF.Description = request.Description;


                var apiResourceClaim = new List<IdentityServer4.EntityFramework.Entities.ApiResourceClaim>();
                if (!string.IsNullOrEmpty(request?.UserClaims))
                {
                    request?.UserClaims.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        apiResourceClaim.Add(new IdentityServer4.EntityFramework.Entities.ApiResourceClaim()
                        {
                            ApiResource = modelEF,
                            ApiResourceId = modelEF.Id,
                            Type = s
                        });
                    });
                    modelEF.UserClaims = apiResourceClaim;
                }


                var apiResourceScopes = new List<IdentityServer4.EntityFramework.Entities.ApiResourceScope>();
                if (!string.IsNullOrEmpty(request?.Scopes))
                {
                    request?.Scopes.Split(",", StringSplitOptions.RemoveEmptyEntries).Where(s => s != "" && s != null).ToList().ForEach(s =>
                    {
                        apiResourceScopes.Add(new IdentityServer4.EntityFramework.Entities.ApiResourceScope()
                        {
                            ApiResource = modelEF,
                            ApiResourceId = modelEF.Id,
                            Scope = s
                        });
                    });
                    modelEF.Scopes = apiResourceScopes;
                }


                var result = (_configurationDbContext.ApiResources.Update(modelEF));
                await _configurationDbContext.SaveChangesAsync();
            }

            return Ok(Url.Action(nameof(Index)));
        }



        /// <summary>
        /// 删除资源api
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Delete(int id)
        {

            try
            {
                var res = await _configurationDbContext.ApiResources.FirstOrDefaultAsync(i => i.Id == id);
                _configurationDbContext.ApiResources.Remove(res);
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
