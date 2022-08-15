using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.Controllers
{
    public class AdminController : BaseController
    {

        public AdminController(UserManager<AppUser> userManager) : base(userManager,null,null)
        {
        }


        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Users()
        {
            return View(_userManager.Users.ToList());
        }
    }
}
