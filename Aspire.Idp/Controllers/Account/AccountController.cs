// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using IdentityServer4.Events;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Identity;
using IdentityServer4.Extensions;
using System.Security.Principal;
using System.Security.Claims;
using IdentityModel;
using System.Linq;
using System;
using System.Collections.Generic;
using Aspire.Idp.Models;
using Microsoft.AspNetCore.Authorization;
using Blog.Core.Common.Helper;
using Microsoft.AspNetCore.Mvc.Routing;
// using static IdentityModel.OidcConstants;
using Newtonsoft.Json;
using System.Text.Json;
using System.ComponentModel;
using Aspire.Idp;
using Microsoft.EntityFrameworkCore;
using System.Web;
using Aspire.Idp.Controllers.Client;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;

namespace IdentityServer4.Quickstart.UI
{
    //[SecurityHeaders]
    [Route("[controller]/[action]")]
    public class AccountController(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        SignInManager<ApplicationUser> signInManager,
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events) : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager = userManager;
        private readonly RoleManager<ApplicationRole> _roleManager = roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
        private readonly IIdentityServerInteractionService _interaction = interaction;
        private readonly IClientStore _clientStore = clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider = schemeProvider;
        private readonly IEventService _events = events;


        /// <summary>
        /// 显示登录页
        /// </summary>
        [HttpGet("/Oauth2/Authorize")]
        public async Task<IActionResult> Login([FromQuery] string ReturnUrl= "/")
        {
            var vm = await BuildLoginViewModelAsync(ReturnUrl);
            if (vm.IsExternalLoginOnly)
            {
                // 我们只有一个登录选项，那就是外部提供商
                return await ExternalLogin(vm.ExternalLoginScheme, ReturnUrl);
            }
            // 已经登录跳转到主页
            if (User.Identity.IsAuthenticated)
            {
                return Redirect(ReturnUrl);
            }
            return View(vm);
        }

        /// <summary>
        /// 登录接口
        /// </summary>
        [HttpPost("/Oauth2/Authorize")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login([FromBody] LoginInputModel model, [FromQuery] string ReturnUrl = "/")
        {
            // 检查我们是否在授权请求的上下文中
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (model.Button != "login")
            {
                if (context != null)
                {
                    //如果用户取消，将结果发送回IdentityServer，就好像他们
                    //拒绝同意(即使此客户端不需要同意)。
                    //这将向客户端发送回拒绝访问OIDC错误响应。
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // 我们可以信任model,ReturnUrl，因为GetAuthorizationContextAsync返回了非空值
                    if (context.IsNativeClient())
                    {
                        //客户端是本机的，因此如何
                        //返回响应是为了给最终用户更好的UX
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // 因为我们没有有效的上下文，所以我们只能返回到主页
                    return Ok(ReturnUrl);
                }
            }

            if (ModelState.IsValid)
            {
                // 邮箱或者登录名
                var user = _userManager.Users.FirstOrDefault(d => (d.UserName == model.UserName || d.Email == model.UserName) && !d.tdIsDelete);

                if (user != null)
                {
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.LoginName));

                        //确保returnUrl 仍然有效，如果有效，则重定向回授权端点或本地页面
                        //仅当您希望支持其他本地页面时，才需要IsLocalUrl检查，否则IsValidReturnUrl会更严格
                        if (_interaction.IsValidReturnUrl(model.ReturnUrl) || Url.IsLocalUrl(model.ReturnUrl))
                        {
                            return Ok(model.ReturnUrl);
                        }
                        return Ok(ReturnUrl);
                    }
                    else
                    {
                        await _events.RaiseAsync(new UserLoginFailureEvent(model.UserName, "无效凭据"));
                    }
                }
                return BadRequest(AccountOptions.InvalidCredentialsErrorMessage);
            }
            return BadRequest(ModelState.SelectMany(i=> i.Value.Errors).FirstOrDefault().ErrorMessage);

        }


        /// <summary>
        /// 显示注册页面
        /// </summary>
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }


        /// <summary>
        /// 注册接口
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            string rName = "SuperAdmin";    // 超级管理员

            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByNameAsync(model.UserName).Result;

                if (userItem == null)
                {
                    var user = new ApplicationUser
                    {
                        RealName = model.UserName,
                        Email = model.Email,
                        UserName = model.UserName,
                        LoginName = model.UserName,
                        sex = model.Sex,
                        age = model.Birth.Year - DateTime.Now.Year,
                        birth = model.Birth,
                        FirstQuestion = model.FirstQuestion,
                        SecondQuestion = model.SecondQuestion,
                        addr = "",
                        tdIsDelete = false
                    };

                    result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        // 添加身份
                        result = await _userManager.AddClaimsAsync(user, new Claim[]{
                            new Claim(JwtClaimTypes.Name, user.UserName),      // 用户登录名（唯一）
                            new Claim(JwtClaimTypes.Email, user.Email),         // 用户邮箱
                            new Claim(JwtClaimTypes.EmailVerified, "false", ClaimValueTypes.Boolean),
                            new Claim(JwtClaimTypes.Role, "4"),
                            new Claim("role_name", rName),
                        });

                        if (result.Succeeded)
                        {
                            // 可以直接登录
                            // await _signInManager.SignInAsync(user, isPersistent: false);
                            return Ok("/");
                        }
                    }
                    return BadRequest(result.Errors.FirstOrDefault()?.Description);

                }
                else
                {
                    return BadRequest($"{userItem.UserName} 用户已经存在");
                }
            }
            else
            {
                return BadRequest(ModelState.SelectMany(i => i.Value.Errors).FirstOrDefault().ErrorMessage);
            }
        }




        /// <summary>
        /// 个人中心页
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> PersonalCenter()
        {
            var id = (int.Parse)(HttpContext.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value);
            if (id <= 0)
            {
                return BadRequest("请重新登录");
            }
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return BadRequest("用户不存在");
            }
            return View(new EditViewModel(
                user.Id.ToString(),
                user.RealName,
                user.UserName,
                user.LoginName,
                user.Email,
                await _userManager.GetClaimsAsync(user),
                user.FirstQuestion,
                user.SecondQuestion)
            );
        }


        /// <summary>
        /// 个人中心编辑
        /// </summary>
        /// <param name="model"></param>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpPut("{id}")]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> PersonalCenter([FromBody] EditViewModel model, string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var _id = (int.Parse)(HttpContext.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value);
                if (_id <= 0)
                {
                    return BadRequest("请重新登录");
                }

                // id为当前登录人
                if (_id.ToString() == id)
                {
                    var user = await _userManager.FindByIdAsync(id);
                    if (user != null)
                    {
                        var oldUserName = user.UserName;
                        var oldEmail = user.Email;

                        user.UserName = model.UserName;
                        user.LoginName = model.LoginName;
                        user.Email = model.Email;
                        user.RealName = model.RealName;
                        user.FirstQuestion = model.FirstQuestion;
                        user.SecondQuestion = model.SecondQuestion;

                        result = await _userManager.UpdateAsync(user);


                        if (result.Succeeded)
                        {
                            var removeClaimsIdRst = await _userManager.RemoveClaimsAsync(user,
                                new Claim[]{
                                new Claim(JwtClaimTypes.Name, oldUserName),
                                new Claim(JwtClaimTypes.Email, oldEmail),
                            });

                            if (removeClaimsIdRst.Succeeded)
                            {
                                var addClaimsIdRst = await _userManager.AddClaimsAsync(user,
                                    new Claim[]{
                                    new Claim(JwtClaimTypes.Name, user.UserName),
                                    new Claim(JwtClaimTypes.Email, user.Email),
                                });

                                if (addClaimsIdRst.Succeeded)
                                {
                                    return Ok("/");
                                }
                                else
                                {
                                    return BadRequest(addClaimsIdRst.Errors.FirstOrDefault().Description);
                                }
                            }
                            else
                            {
                                return BadRequest(removeClaimsIdRst.Errors.FirstOrDefault().Description);
                            }
                        }
                        else
                        {
                            return BadRequest(result.Errors.FirstOrDefault().Description);
                        }
                    }
                    else
                    {
                        return BadRequest("用户不存在");
                    }
                }
                else
                {
                    return BadRequest("只能修改自己的信息");
                }
            }
            else
            {
                return BadRequest(ModelState.SelectMany(i=> i.Value.Errors).FirstOrDefault().ErrorMessage);
            }
        }



        /// <summary>
        /// 注销
        /// </summary>
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> Logout([FromQuery] string logoutId)
        {
            // 构建一个模型，以便注销的页面知道要显示什么
            var vm = await BuildLoggedOutViewModelAsync(logoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // 删除本地身份验证cookie
                await _signInManager.SignOutAsync();

                // 引发注销事件
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // 检查我们是否需要在上游身份提供者处触发注销
            if (vm.TriggerExternalSignout)
            {
                //建立一个返回URL，这样上游提供者将重定向回来
                //在用户注销后发送给我们。这让我们可以
                //完成我们的单点登出处理。
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // 这将触发对外部提供商的重定向，以便注销
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }
            return Redirect(vm?.PostLogoutRedirectUri??"/");
        }




        /// <summary>
        /// 显示用户表格页
        /// </summary>
        /// <param name="page"></param>
        /// <param name="rows"></param>
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Users(int page,int rows)
        {
            try
            {
                if (page < 1 || rows < 1)
                {
                    return View();
                }
                var res = await _userManager.Users
                    .Where(d => !d.tdIsDelete)
                    .OrderByDescending(d => d.Id)
                    .Skip((page - 1) * rows)
                    .Take(rows)
                .ToListAsync();


                return Json(new MessageModel()
                {
                    success = true,
                    msg = "获取成功",
                    response = new
                    {
                        data = res,
                        total = await _userManager.Users.CountAsync(i => !i.tdIsDelete),
                    }
                });

            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }


        /// <summary>
        /// 显示用户编辑页
        /// </summary>
        /// <param name="id"></param>
        /// <param name="returnUrl"></param>
        [HttpGet("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Edit(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return BadRequest("用户不存在");
            }
            return View(new EditViewModel(user.Id.ToString(), user.RealName, user.UserName, user.LoginName, user.Email, await _userManager.GetClaimsAsync(user), user.FirstQuestion, user.SecondQuestion));
        }



        /// <summary>
        /// 编辑用户信息
        /// </summary>
        /// <param name="model"></param>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpPut("{id}")]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Edit([FromBody] EditViewModel model, string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var user = _userManager.FindByIdAsync(id).Result;

                if (user != null)
                {
                    var oldName = user.UserName;
                    var oldEmail = user.Email;

                    user.UserName = model.UserName;
                    user.LoginName = model.LoginName;
                    user.Email = model.Email;
                    user.RealName = model.RealName;
                    user.Id = Convert.ToInt32(id);

                    result = await _userManager.UpdateAsync(user);

                    if (result.Succeeded)
                    {
                        var removeClaimsIdRst = await _userManager.RemoveClaimsAsync(user,
                            new Claim[]{
                                new Claim(JwtClaimTypes.Name, oldName),
                                new Claim(JwtClaimTypes.Email, oldEmail),
                        });

                        if (removeClaimsIdRst.Succeeded)
                        {
                            var addClaimsIdRst = await _userManager.AddClaimsAsync(user,
                                new Claim[]{
                                    new Claim(JwtClaimTypes.Name, user.UserName),
                                    new Claim(JwtClaimTypes.Email, user.Email),
                            });

                            if (addClaimsIdRst.Succeeded)
                            {
                                return Ok(Url.Action(nameof(Users)));
                            }
                            else
                            {
                                return BadRequest(addClaimsIdRst.Errors.FirstOrDefault().Description);
                            }
                        }
                        else
                        {
                            return BadRequest(removeClaimsIdRst.Errors.FirstOrDefault().Description);
                        }
                    }
                    else
                    {
                        return BadRequest(result.Errors.FirstOrDefault().Description);
                    }
                }
                else
                {
                    return BadRequest("用户不存在");
                }
            }
            else
            {
                return BadRequest(ModelState.SelectMany(i=>i.Value.Errors).FirstOrDefault().ErrorMessage);
            }
        }


        /// <summary>
        /// 删除用户
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpDelete("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> Delete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var userItem = _userManager.FindByIdAsync(id).Result;
                if (userItem != null)
                {
                    userItem.tdIsDelete = true;
                    result = await _userManager.UpdateAsync(userItem);
                    if (result.Succeeded)
                    {
                        return Ok();
                    }
                    else
                    {
                        return BadRequest(result.Errors.FirstOrDefault().Description);
                    }
                }
                else
                {
                    return BadRequest("用户不存在");
                }
            }
            else
            {
                return BadRequest(ModelState.SelectMany(i => i.Value.Errors).FirstOrDefault().ErrorMessage);
            }

        }


        /// <summary>
        /// 找回密码页
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        /// <summary>
        /// 忘记密码提交页
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var email = HttpContext.User.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                var roleName = HttpContext.User.Claims.FirstOrDefault(c => c.Type == "role_name")?.Value;

                // 管理员验证邮箱即可
                if (email == model.Email || (roleName == "SuperAdmin"))
                {

                    var user = await _userManager.FindByEmailAsync(model.Email);
                    //if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                    if (user == null)
                    {
                        return BadRequest("邮箱不存在！");
                    }

                    //有关如何启用帐户确认和密码重置的更多信息，请
                    // visit https://go.microsoft.com/fwlink/?LinkID=532713
                    var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var accessCode = MD5Helper.MD5Encrypt32(user.Id + code);
                    var callbackUrl = Url.ResetPasswordCallbackLink(user.Id.ToString(), code, Request.Scheme, accessCode);

                    // 跳转到重置密码的链接
                    return Ok(callbackUrl);

                }
                else if (!string.IsNullOrEmpty(model.FirstQuestion) && !string.IsNullOrEmpty(model.SecondQuestion))
                {
                    var user = _userManager.Users.FirstOrDefault(d => d.Email == model.Email && d.FirstQuestion == model.FirstQuestion && d.SecondQuestion == model.SecondQuestion);
                    if (user == null)
                    {
                        return BadRequest("密保答案错误！");
                    }

                    var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var accessCode = MD5Helper.MD5Encrypt32(user.Id + code);
                    var callbackUrl = Url.ResetPasswordCallbackLink(user.Id.ToString(), code, Request.Scheme, accessCode);

                    // 跳转到重置密码的链接
                    return Ok(callbackUrl);
                }
                else
                {
                    return BadRequest("无权访问");
                }
            }
            return BadRequest("参数错误");
        }


        /// <summary>
        /// 重置密码页
        /// </summary>
        /// <param name="code"></param>
        /// <param name="accessCode"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null, string accessCode = null, string userId = "")
        {
            // 已经登录
            if (User.Identity.IsAuthenticated)
            {
                var user = _userManager.FindByNameAsync(User.Identity.Name).Result;
                code = _userManager.GeneratePasswordResetTokenAsync(user).Result;
                accessCode = MD5Helper.MD5Encrypt32(user.Id + code);

                // 跳转到重置密码的链接
                var model = new ResetPasswordViewModel { Code = code, AccessCode = accessCode, userId = user.Id.ToString() };
                return View(model);
            }
            else
            {
                if (code == null || accessCode == null)
                {
                    return RedirectToAction(nameof(AccessDenied), new { errorMsg = "code与accessCode必须都不能为空！" });
                }
                var model = new ResetPasswordViewModel { Code = code, AccessCode = accessCode, userId = userId };
                return View(model);
            }
           
        }


        /// <summary>
        /// 重置密码
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPut]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(model.userId);
                if (user == null)
                {
                    return BadRequest("用户不存在");
                }

               model.Code = HttpUtility.HtmlDecode(model.Code);
               // 防止篡改
               var getAccessCode = MD5Helper.MD5Encrypt32(model.userId + model.Code);
                if (getAccessCode != model.AccessCode)
                {
                    return BadRequest("随机码已被篡改！密码重置失败！");
                }

                if (user != null && user.Id.ToString() != model.userId)
                {
                    return BadRequest("不能修改他人邮箱！密码重置失败！");
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    return Ok(Url.Action(nameof(Login)));
                }
                else
                {
                    return BadRequest(result.Errors.FirstOrDefault().Description);
                }
            }
            else
            {
                return BadRequest(ModelState.SelectMany(i => i.Value.Errors).FirstOrDefault().ErrorMessage);
            }
        }





        /// <summary>
        /// 邮箱确认页
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        /// <exception cref="ApplicationException"></exception>
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        /// <summary>
        /// 无权限页
        /// </summary>
        /// <param name="errorMsg"></param>
        /// <returns></returns>
        [HttpGet]
        public IActionResult AccessDenied(string errorMsg = "")
        {
            ViewBag.ErrorMsg = errorMsg;
            return View();
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }


        // Role Manager

        [HttpGet]
        public IActionResult RoleRegister(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RoleRegister(RoleRegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var roleItem = _roleManager.FindByNameAsync(model.RoleName).Result;

                if (roleItem == null)
                {

                    var role = new ApplicationRole
                    {
                        Name = model.RoleName
                    };


                    result = await _roleManager.CreateAsync(role);

                    if (result.Succeeded)
                    {

                        if (result.Succeeded)
                        {
                            // 可以直接登录
                            //await _signInManager.SignInAsync(user, isPersistent: false);

                            return RedirectToLocal(returnUrl);
                        }
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} already exists");

                }

                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }


        [HttpGet]
        [Authorize]
        public IActionResult Roles(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var roles = _roleManager.Roles.Where(d => !d.IsDeleted).ToList();

            return View(roles);
        }



        [HttpGet("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> RoleEdit(string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (id == null)
            {
                return NotFound();
            }

            var user = await _roleManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(new RoleEditViewModel(user.Id.ToString(), user.Name));
        }


        [HttpPost("{id}")]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> RoleEdit(RoleEditViewModel model, string id, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var roleItem = _roleManager.FindByIdAsync(model.Id).Result;

                if (roleItem != null)
                {
                    roleItem.Name = model.RoleName;


                    result = await _roleManager.UpdateAsync(roleItem);

                    if (result.Succeeded)
                    {
                        return RedirectToLocal(returnUrl);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} no exist!");
                }

                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }



        [HttpDelete("{id}")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<JsonResult> RoleDelete(string id)
        {
            IdentityResult result = new IdentityResult();

            if (ModelState.IsValid)
            {
                var roleItem = _roleManager.FindByIdAsync(id).Result;

                if (roleItem != null)
                {
                    roleItem.IsDeleted = true;


                    result = await _roleManager.UpdateAsync(roleItem);

                    if (result.Succeeded)
                    {
                        return Json(result);
                    }

                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"{roleItem?.Name} no exist!");
                }

                AddErrors(result);
            }

            return Json(result.Errors);

        }

        /// <summary>
        /// 启动到外部身份验证提供程序的往返
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
        {
            if (AccountOptions.WindowsAuthenticationSchemeName == provider)
            {
                // windows authentication needs special handling
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // start challenge and roundtrip the return URL and 
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("ExternalLoginCallback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", provider },
                    }
                };
                return Challenge(props, provider);
            }
        }

        /// <summary>
        /// 外部认证的后处理
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);


            //这可能是您为用户注册启动自定义工作流的地方
            //在这个示例中，我们没有展示如何实现，作为我们的示例实现
            //简单地自动设置新的外部用户
            user ??= await AutoProvisionUserAsync(provider, providerUserId, claims);




            // this allows us to collect any additonal claims or properties
            // for the specific prtotocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForWsFed(result, additionalLocalClaims, localSignInProps);
            ProcessLoginCallbackForSaml2p(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            // we must issue the cookie maually, and can't use the SignInManager because
            // it doesn't expose an API to issue additional claims from the login workflow
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);
            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id.ToString();
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id.ToString(), name));

            //await HttpContext.SignInAsync(user.Id.ToString(), name, provider, localSignInProps, additionalLocalClaims.ToArray());

            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await HttpContext.SignInAsync(isuser, localSignInProps);


            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // validate return URL and redirect back to authorization endpoint or a local page
            var returnUrl = result.Properties.Items["returnUrl"];
            if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Redirect("~/");
        }







        /*****************************************/
        /* AccountController的助手API */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    UserName = context?.LoginHint,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,    // 是否本地登录
                ReturnUrl = returnUrl,
                UserName = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.UserName = model.UserName;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        // if there's no current logout context, we need to create one
                        // this captures necessary info from the current logged in user
                        // before we signout and redirect away to the external IdP for signout
                        vm.LogoutId ??= await _interaction.CreateLogoutContextAsync();

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }


        /// <summary>
        /// windows上才能使用
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
       
        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);

            if (result?.Principal is WindowsPrincipal wp && RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, tresting windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("ExternalLoginCallback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));


                // 将组作为声明添加——如果组的数量太大，要小心
                if (AccountOptions.IncludeWindowsGroups)
                {
                
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    #pragma warning disable CA1416 // 验证平台兼容性
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    #pragma warning restore CA1416 // 验证平台兼容性
                    id.AddClaims(roles);
                }



                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }

        private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)>
            FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        private async Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
               claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var user = new ApplicationUser
            {
                UserName = Guid.NewGuid().ToString(),
            };
            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            return user;
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private void ProcessLoginCallbackForWsFed(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }

        private void ProcessLoginCallbackForSaml2p(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
        }



       
    }
}
