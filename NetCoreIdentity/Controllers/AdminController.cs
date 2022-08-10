using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.Controllers
{
    public class AdminController : Controller
    {

        private readonly UserManager<AppUser> userManager;

        public AdminController(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }


        public IActionResult Index()
        {
            return View(userManager.Users.ToList());
        }
    }
}
