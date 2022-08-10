using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetCoreIdentity.Models;
using NetCoreIdentity.Models.ViewModel;

namespace NetCoreIdentity.Controllers
{
    public class HomeController : Controller
    {

        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;

        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult LogIn(string retunUrl)
        {
            TempData["retunUrl"] = retunUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    await _signInManager.SignOutAsync();
                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
                    if (result.Succeeded)
                    {
                        if (TempData["retunUrl"] != null)
                        {
                            return Redirect(TempData["retunUrl"].ToString());
                        }
                        return RedirectToAction("Index", "Member");
                    }
                }
            }
            ModelState.AddModelError("","Geçersiz Kullanıcı Adı veya Parola");
            return View();
        }

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
                    return RedirectToAction("LogIn");
                }
                else
                {
                    foreach (var err in result.Errors)
                    {
                        ModelState.AddModelError("",err.Description);
                    }
                }

            }
            return View(user);
        }

    }
}
