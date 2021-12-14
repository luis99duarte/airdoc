// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using identity.Models;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;
using identity;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using NETCore.MailKit.Core;

namespace identity.Controllers
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly ILogger _logger;
        private readonly IEmailService _emailService;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            ILogger<AccountController> logger,
            IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _logger = logger;
            _emailService = emailService;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {

           
            _logger.LogInformation(" Starting Login received the return URL : >>>  " + returnUrl + " <<< ");


            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request

            _logger.LogInformation(" Login >>> getting context for " + model.ReturnUrl + " <<< ");

            
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (context != null)
            {
                _logger.LogInformation("Context  >>>" + context.ToString() + "<<<");
            }
            else {

                _logger.LogInformation("Context  >>> ESTA NULO <<<");
            }

            if (button == "newUser") {
                return RedirectToAction("Register", model);
            }

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);
                    /*
                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (await _clientStore.IsPkceClientAsync(context.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }
                    */
                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            _logger.LogInformation("Model State  >>>" + ModelState.IsValid + "<<<");

            if (ModelState.IsValid)
            {


                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);

                _logger.LogInformation("Result from Password State  >>>" + result.Succeeded + "<<<");

                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.ClientId));

                    if (context != null)
                    {/*
                        if (await _clientStore.IsPkceClientAsync(context.ClientId))
                        {
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }
                        */
                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null

                        _logger.LogInformation("Context is not null  >>>" + context + " going for " + model.ReturnUrl+" <<<");

                        // Verify if the user has a verified email. If not it will redirect to a verify
                        // email or skip page
                        if(await _userManager.IsEmailConfirmedAsync(user))
                            return Redirect(model.ReturnUrl);

                        else
                        {
                            // return <view for email verification>
                            return RedirectToAction("EmailVerification", model);
                        }
                        
                    }

                    _logger.LogInformation("RETURN URL >>>" + model.ReturnUrl + "<<<");

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged

                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            _logger.LogInformation("NO AUTH  >>>" + model.ToString() + "<<<");
            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }


        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        /// <summary>
        /// Entry point into the registration workflow
        /// </summary>
        [HttpGet]
        public IActionResult Register(string rememberLogin, string returnUrl)
        {

            // build a model so we know what to show on the login page
            List<SelectListItem> Roles = new List<SelectListItem>();
            var _roles = _roleManager.Roles.ToList();
            var count = _roles.Count;
            for (int i = 0; i < count; i++)
            {
                if (_roles[i].Name != "User" && _roles[i].Name != "Practicioner")
                    Roles.Add(new SelectListItem(_roles[i].Name, _roles[i].NormalizedName));
            }
            return View(new RegisterViewModel(Roles, returnUrl));
        }


        /// <summary>
        /// Entry point into the registration workflow
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string button)
        {
            
            if (button == "Cancel") {
                return Redirect("~/");
            }
            var appUser = new ApplicationUser();

            appUser.UserName = model.Username;

            appUser.Email = model.Email; 
            appUser.EmailConfirmed = true;


            if (model.Password != model.ConfirmPassword) {

                Console.WriteLine("Passwords do not match ");
                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "passwords não coincidem"));

                ModelState.AddModelError(string.Empty, AccountOptions.InvalidPasswordIdenticalErrorMessage);

            } 
            else {

                if (model.Email != model.ConfirmEmail)
                {
                    Console.WriteLine("Emails do not match ");
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "emails não coincidem"));

                    ModelState.AddModelError(string.Empty, AccountOptions.InvalidEmailIdenticalErrorMessage);
                }

                else
                {
                    IdentityResult result = await _userManager.CreateAsync(appUser, model.Password);

                    if (result.Succeeded)
                    {
                        result = await _userManager.AddToRolesAsync(appUser, new[] { "USER", model.Role });

                        if (result.Succeeded)
                        {
                            Console.WriteLine("Vou colocar o email");
                            result = await _userManager.SetEmailAsync(appUser, model.Email);

                            if (result.Succeeded)
                            {

                                var token = _userManager.GenerateEmailConfirmationTokenAsync(appUser);
                                string castvar = (string)await token;
                                var verificationLink = Url.Action("VerifyEmail", "Account", new { userId = appUser.Id, token = castvar }, Request.Scheme);
                                _logger.Log(LogLevel.Warning, verificationLink);
                                await _emailService.SendAsync(model.Email, "Verify Your Email", $"<a href=\"{verificationLink}\">Verify Email</a>", true);

                                Console.WriteLine("coloquei o email");
                            }
                            Claim test = new Claim("display_name", model.Username);

                            result = await _userManager.AddClaimAsync(appUser, test);

                            if (result.Succeeded)
                            {
                                //return Redirect("~/");
                                return RedirectToAction("Login", model);
                            }
                        }
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                }
            }

            var vm = await BuildRegisterViewModelAsync(model);
            return View(vm);




            /*
            // build a model so we know what to show on the login page
            List<SelectListItem> Roles = new List<SelectListItem>();
            var _roles = _roleManager.Roles.ToList();
            var count = _roles.Count;
            for (int i = 0; i < count; i++)
            {
                if (_roles[i].Name != "User")
                    Roles.Add(new SelectListItem(_roles[i].Name, _roles[i].Id));
            }
            return View(new RegisterViewModel(Roles));

            */

        }

        [AllowAnonymous]
        public async Task<IActionResult> VerifyEmail(string userId, string token)
        {
            if(userId == null || token == null) {
                return RedirectToAction("index", "home");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                ViewBag.ErrorMessage = $"The User ID {userId} is invalid";
                return View("NotFound");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if(result.Succeeded)
            {
                return View("EmailVerification");
            }

            ViewBag.ErrorTitle = "Email cannot be confirmed";
            return View("Error");
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Find the user by email
                var user = await _userManager.FindByEmailAsync(model.Email);
                /*          If there is email confirmation
                 * // If the user is found AND Email is confirmed
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    // Generate the reset password token
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    // Build the password reset link
                    var passwordResetLink = Url.Action("ResetPassword", "Account",
                            new { email = model.Email, token = token }, Request.Scheme);

                    // Log the password reset link
                    _logger.Log(LogLevel.Warning, passwordResetLink);

                    // Send the user to Forgot Password Confirmation view
                    return View("ForgotPasswordConfirmation");
                }
                */
                
                // If the email provided isn't valid the view is returned
                // to avoid account enumeration and brute force attacks
                if(user == null)
                    return View("ForgotPasswordConfirmation");

                // Generate the reset password token
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                // Build the password reset link
                var passwordResetLink = Url.Action("ResetPassword", "Account", new { email = model.Email, token = token }, Request.Scheme);

                // Sends the email through the MailKit
                await _emailService.SendAsync(model.Email, "Reset Your Password",$"<a href=\"{passwordResetLink}\">Reset Password</a>", true);

                // Log the password reset link
                _logger.Log(LogLevel.Warning, passwordResetLink);

                // Send the Forgot Password Confirmation view
                return View("ForgotPasswordConfirmation");
            }

            return View(model);
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string email)
        {
            // If password reset token or email is null, most likely the
            // user tried to tamper the password reset link
            if (token == null || email == null)
            {
                ModelState.AddModelError("", "Invalid password reset token");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Find the user by email
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    // reset the user password
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
                    {
                        return View("ResetPasswordConfirmation");
                    }
                    // Display validation errors. For example, password reset token already
                    // used to change the password or password complexity rules not met
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(model);
                }

                // To avoid account enumeration and brute force attacks, don't
                // reveal that the user does not exist
                return View("ResetPasswordConfirmation");
            }
            // Display validation errors if model state is not valid
            return View(model);
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };
                /*  
                  if (!local)
                  {
                      vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                  }
                  */
                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            /*  var providers = schemes
                  .Where(x => x.DisplayName != null ||
                              (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                  )
                  .Select(x => new ExternalProvider
                  {
                      DisplayName = x.DisplayName,
                      AuthenticationScheme = x.Name
                  }).ToList();
                  */
            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;
                    /*
                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                    */
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,

            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(RegisterViewModel model)
        {
            var vm = await BuildRegisterViewModelAsync(model.ReturnUrl, model.Roles);
            return vm;
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(string returnUrl, List<SelectListItem> RolesList)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            // build a model so we know what to show on the login page
            List<SelectListItem> Roles = new List<SelectListItem>();
            var _roles = _roleManager.Roles.ToList();
            var count = _roles.Count;
            for (int i = 0; i < count; i++)
            {
                if (_roles[i].Name != "User")
                    Roles.Add(new SelectListItem(_roles[i].Name, _roles[i].NormalizedName));
            }


            if (context?.IdP != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP

                var vm = new RegisterViewModel(Roles, returnUrl);

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                }
            }

            return new RegisterViewModel(Roles, returnUrl);
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
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}