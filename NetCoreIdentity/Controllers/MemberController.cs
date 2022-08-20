using System.Security.Claims;
using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using NetCoreIdentity.Enums;
using NetCoreIdentity.Models;
using NetCoreIdentity.Models.ViewModel;

namespace NetCoreIdentity.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {

        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager) : base(userManager, signInManager)
        {
        }

        public async Task<IActionResult> Index()
        {
            AppUser user = CurrentUser;
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }



        #region PasswordChange

        public IActionResult PasswordChange()
        {
            return View();
        }

        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChangeViewModel)
        {
            if (ModelState.IsValid)
            {
                AppUser user = _userManager.FindByNameAsync(User.Identity.Name).Result;

                bool exist = _userManager.CheckPasswordAsync(user, passwordChangeViewModel.PasswordOld).Result;

                if (exist)
                {
                    IdentityResult result = _userManager.ChangePasswordAsync(user, passwordChangeViewModel.PasswordOld, passwordChangeViewModel.PasswordNew).Result;

                    if (result.Succeeded)
                    {
                        _userManager.UpdateSecurityStampAsync(user);

                        _signInManager.SignOutAsync();
                        _signInManager.PasswordSignInAsync(user, passwordChangeViewModel.PasswordNew, true, false);

                        ViewBag.success = "true";
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
                    ModelState.AddModelError("", "Eski şifreniz yanlış");
                }
            }

            return View(passwordChangeViewModel);
        }

        #endregion

        #region UserEdit

        public IActionResult UserEdit()
        {
            AppUser user = CurrentUser;

            UserViewModel userViewModel = user.Adapt<UserViewModel>();
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));

            return View(userViewModel);
        }

        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile userPicture = null)
        {
            ModelState.Remove("Password");
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));

            if (ModelState.IsValid)
            {
                AppUser user = CurrentUser;

                if (userPicture != null && userPicture.Length > 0)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(userPicture.FileName);

                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/UserPicture", fileName);

                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await userPicture.CopyToAsync(stream);

                        user.Picture = "/UserPicture/" + fileName;
                    }
                }

                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int)userViewModel.Gender;

                IdentityResult result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    await _userManager.UpdateSecurityStampAsync(user);
                    await _signInManager.SignOutAsync();
                    await _signInManager.SignInAsync(user, true);

                    ViewBag.success = "true";
                    return RedirectToAction("Index", "Member");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }
                }
            }

            return View(userViewModel);
        }

        #endregion

        public void LogOut()
        {
            _signInManager.SignOutAsync();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [Authorize(Roles = "Editör")]
        public IActionResult Edıtor()
        {
            return View();
        }

        
        [Authorize(Roles = "Super Admin")]
        public IActionResult SuperAdmin()
        {
            return View();
        }

        [Authorize(Policy = "SamsunPolicy")]
        public IActionResult SamsunPage()
        {
            return View();
        }

        [Authorize(Roles="Super Admin",Policy = "ViolencePolicy")]
        public IActionResult ViolancePage()
        {
            return View();
        }
        
        public async Task<IActionResult> ExchangeRedirect()
        {
            var result = User.HasClaim(x => x.Type == "ExpireDateExchange");
            if (!result)
            {
                await _userManager.AddClaimAsync(CurrentUser,
                    new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).ToString(), ClaimValueTypes.String,"Internal"));
                await _signInManager.SignOutAsync();
                await _signInManager.SignInAsync(CurrentUser, true);
            }
            
            return RedirectToAction("Exchange", "Member");
        }
        
        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult Exchange()
        {
            return View();
        }

        public IActionResult TwoFactorAuth()
        {
            return View(new AuthenticatorViewModel() { TwoFactorType = (TwoFactor)CurrentUser.TwoFactor });
        }
    }
}
