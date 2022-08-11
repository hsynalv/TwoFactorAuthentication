using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetCoreIdentity.Models;
using NetCoreIdentity.Models.ViewModel;

namespace NetCoreIdentity.Controllers
{
    public class MemberController : Controller
    {

        public UserManager<AppUser> userManager { get; }
        public SignInManager<AppUser> signInManager { get; }

        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }
        
        public async Task<IActionResult> Index()
        {
            AppUser user = await userManager.FindByNameAsync(User.Identity.Name);
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }
    }
}
