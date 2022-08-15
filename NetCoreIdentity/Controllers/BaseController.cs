using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.Controllers
{
    public class BaseController : Controller
    {
        protected UserManager<AppUser> _userManager { get; }
        protected SignInManager<AppUser> _signInManager { get; }
        protected RoleManager<IdentityRole> _roleManager { get; }
        protected AppUser CurrentUser => _userManager.FindByNameAsync(User.Identity.Name).Result;
    
        public BaseController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
            this._roleManager = roleManager;
        }
        
        public BaseController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
        }
        
        public BaseController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            this._userManager = userManager;
            this._signInManager = null;
            this._roleManager = roleManager;
        }
    
        public void AddModelError(IdentityResult result)
        {
            foreach (var item in result.Errors)
            {
                ModelState.AddModelError("", item.Description);
            }
        }
    }
    
}
