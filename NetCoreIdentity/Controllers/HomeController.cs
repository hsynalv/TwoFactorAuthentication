using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetCoreIdentity.Helper;
using NetCoreIdentity.Models;
using NetCoreIdentity.Models.ViewModel;

namespace NetCoreIdentity.Controllers
{
    public class HomeController : BaseController
    {
        private LoginViewModel _loginViewModel;

        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base(userManager, signInManager)
        {
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

        public IActionResult LogIn(string retunUrl)
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

                    await _signInManager.SignOutAsync();
                    var result = await _signInManager.PasswordSignInAsync(user, loginViewModel.Password,
                        loginViewModel.RememberMe, false);
                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);

                        if (TempData["retunUrl"] != null)
                        {
                            return Redirect(TempData["retunUrl"].ToString());
                        }

                        return RedirectToAction("Index", "Member");
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
                    PhoneNumber = user.PhoneNumber
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

        
    }
}
