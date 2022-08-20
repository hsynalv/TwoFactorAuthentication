using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetCoreIdentity.Enums;
using NetCoreIdentity.Helper;
using NetCoreIdentity.Models;
using NetCoreIdentity.Models.ViewModel;
using NetCoreIdentity.TwoFactorServices;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace NetCoreIdentity.Controllers
{
    public class HomeController : BaseController
    {
        private LoginViewModel _loginViewModel;

        private readonly TwoFactorService _twoFactorService;

        private readonly EmailSender _emailSender;

        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService twoFactorService, EmailSender emailSender) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }

            return View();
        }


        #region LogIn

        public IActionResult LogIn(string retunUrl="/")
        {
            TempData["retunUrl"] = retunUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);
                if (user != null)
                {
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("",
                            "Hesabınız bir süreliğine kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");

                        return View(loginViewModel);
                    }

                    //if (_userManager.IsEmailConfirmedAsync(user).Result == false)
                    //{
                    //    ModelState.AddModelError("","Email adresiniz doğrulanmamıştır, lütfen emailinizi kontrol ediiz.");
                    //    return View(loginViewModel);
                    //}


                    bool userCheck = await _userManager.CheckPasswordAsync(user, loginViewModel.Password);
                    if (userCheck)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _signInManager.SignOutAsync();
                        var result = await _signInManager.PasswordSignInAsync(user, loginViewModel.Password, loginViewModel.RememberMe, false);

                        if (result.RequiresTwoFactor)
                        {
                            if (user.TwoFactor == (int)TwoFactor.Email || user.TwoFactor == (int)TwoFactor.Phone)
                            {
                                HttpContext.Session.Remove("currentTime");
                            }
                            return RedirectToAction("TwoFactorLogIn", "Home", new { ReturnUrl = TempData["ReturnUrl"].ToString() });
                        }
                        else
                        {
                            return Redirect(TempData["retunUrl"].ToString());
                        }
                    }
                    else
                    {
                        await _userManager.AccessFailedAsync(user);

                        int fail = await _userManager.GetAccessFailedCountAsync(user);
                        ModelState.AddModelError("", $" {fail} kez başarısız giriş.");
                        if (fail == 3)
                        {
                            await _userManager.SetLockoutEndDateAsync(user,
                                new DateTimeOffset(DateTime.Now.AddMinutes(20)));

                            ModelState.AddModelError("",
                                "Hesabınız 3 başarısız girişten dolayı 20 dakika süreyle kitlenmiştir. Lütfen daha sonra tekrar deneyiniz.");
                        }
                        else
                        {
                            ModelState.AddModelError("", "Email adresiniz veya şifreniz yanlış.");
                        }
                    }
                }
            }

            ModelState.AddModelError("", "Geçersiz Kullanıcı Adı veya Parola");
            return View();
        }

        #endregion

        #region SignUp

        public IActionResult SignUp()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel user)
        {
            if (ModelState.IsValid)
            {
                var _user = new AppUser
                {
                    UserName = user.UserName,
                    Email = user.Email,
                    PhoneNumber = user.PhoneNumber,
                    TwoFactor = (sbyte?)TwoFactor.None,

                };

                var result = await _userManager.CreateAsync(_user, user.Password);
                if (result.Succeeded)
                {

                    //string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(_user);
                    //string link = Url.Action("ConfirmEmail", "Home",
                    //    new { userId = _user.Id, token = confirmationToken }, Request.Scheme);

                    //Helper.EmailConfirmation.SendEmail(link, _user.Email);



                    return RedirectToAction("LogIn");
                }
                else
                {
                    foreach (var err in result.Errors)
                    {
                        ModelState.AddModelError("", err.Description);
                    }
                }

            }

            return View(user);
        }

        #endregion

        #region ResetPassword

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(PasswordResetViewModel viewModel)
        {
            var user = await _userManager.FindByEmailAsync(viewModel.Email);

            if (user != null)
            {
                string passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                string passwordResetLink = Url.Action("ResetPasswordConfirm", "Home",
                    new { userId = user.Id, token = passwordResetToken }, Request.Scheme);

                PasswordReset.SendPasswordResetEmail(passwordResetLink, viewModel.Email);

                ViewBag.status = "Parola sıfırlama linki gönderildi.";
            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı e-posta adresi bulunamamıştır");
            }



            return View(viewModel);
        }

        #endregion

        #region ResetPasswordConfirm

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPasswordConfirm(
            [Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {
            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            AppUser user = await _userManager.FindByIdAsync(userId);

            if (user != null)
            {
                IdentityResult result =
                    await _userManager.ResetPasswordAsync(user, token, passwordResetViewModel.PasswordNew);

                if (result.Succeeded)
                {
                    await _userManager.UpdateSecurityStampAsync(user);

                    ViewBag.status = "success";
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }
                }
            }
            else
            {
                ModelState.AddModelError("", "hata meydana gelmiştir. Lütfen daha sonra tekrar deneyiniz.");
            }

            return View(passwordResetViewModel);
        }

        #endregion

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                ViewBag.status = "Email adresiniz onaylanmıştır. Login ekranından giriş yapabilirsiniz.";
            }
            else
            {
                ViewBag.status = "Bir hata meydana geldi. lütfen daha sonra tekrar deneyiniz.";
            }
            return View();
        }

        #region ExternalLogin

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            return new ChallengeResult("Facebook", properties);
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);

            return new ChallengeResult("Google", properties);
        }

        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);

            return new ChallengeResult("Microsoft", properties);
        }
        
        #endregion

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            ExternalLoginInfo info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("LogIn");
            }
            else
            {
                SignInResult result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                if (result.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToAction("TwoFactorLogin");
                }
                else
                {
                    AppUser user = new AppUser();

                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;

                        userName = userName.Replace(' ', '-').ToLower() + ExternalUserId.Substring(0, 5).ToString();

                        user.UserName = userName;
                    }
                    else
                    {
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }

                    AppUser user2 = await _userManager.FindByEmailAsync(user.Email);

                    if (user2 == null)
                    {
                        IdentityResult createResult = await _userManager.CreateAsync(user);

                        if (createResult.Succeeded)
                        {
                            IdentityResult loginResult = await _userManager.AddLoginAsync(user, info);

                            if (loginResult.Succeeded)
                            {
                                //     await signInManager.SignInAsync(user, true);

                                await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                                return Redirect(ReturnUrl);
                            }
                            else
                            {
                                AddModelError(loginResult);
                            }
                        }
                        else
                        {
                            AddModelError(createResult);
                        }
                    }
                    else
                    {
                        IdentityResult loginResult = await _userManager.AddLoginAsync(user2, info);

                        await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                        return Redirect(ReturnUrl);
                    }
                }
            }

            List<string> errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();

            return View("Error", errors);
        }


        public IActionResult Error()
        {
            return View();
        }

        #region TwoFactorLogin

        public async Task<IActionResult> TwoFactorLogin(string ReturnUrl = "/")
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            TempData["ReturnUrl"] = ReturnUrl;

            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.MicrosoftGoogle:
                    break;
                case TwoFactor.Email:

                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("Login");
                    }

                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);

                    HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));

                    break;
            }

            return View(new TwoFactorLoginViewModel() { TwoFactorType = (TwoFactor)user.TwoFactor, isRecoverCode = false, isRememberMe = false, VerificationCode = string.Empty });
        }
        
        [HttpPost]
        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginViewModel twoFactorLoginView)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            ModelState.Clear();
            bool isSuccessAuth = false;

            if ((TwoFactor)user.TwoFactor == TwoFactor.MicrosoftGoogle)
            {
                SignInResult result;

                if (twoFactorLoginView.isRecoverCode)
                {
                    result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLoginView.VerificationCode);
                }
                else
                {
                    result = await _signInManager.TwoFactorAuthenticatorSignInAsync(twoFactorLoginView.VerificationCode, twoFactorLoginView.isRememberMe, false);
                }
                if (result.Succeeded)
                {
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodu yanlış");
                }
            }
            else if (user.TwoFactor == (sbyte)TwoFactor.Email || user.TwoFactor == (int)TwoFactor.Phone)
            {
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                if (twoFactorLoginView.VerificationCode == HttpContext.Session.GetString("codeVerification"))

                {
                    await _signInManager.SignOutAsync();

                    await _signInManager.SignInAsync(user, twoFactorLoginView.isRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeVerification");
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodu yanlış");
                }
            }

            if (isSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }
            twoFactorLoginView.TwoFactorType = (TwoFactor)user.TwoFactor;

            return View(twoFactorLoginView);
        }

        #endregion

        



    }
}
