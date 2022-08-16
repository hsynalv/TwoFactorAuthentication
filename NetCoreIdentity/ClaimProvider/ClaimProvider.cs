using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.ClaimProvider
{
    public class ClaimProvider : IClaimsTransformation
    {

        private UserManager<AppUser> _userManager { get; set; }
        public ClaimProvider(UserManager<AppUser> userManager)
        {
            this._userManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                ClaimsIdentity identity = principal.Identity as ClaimsIdentity;

                var user = await _userManager.FindByNameAsync(identity.Name);

                if (user != null)
                {
                    if (user.City != null)
                    {
                        if (!principal.HasClaim(c => c.Type == "City"))
                        {
                            identity.AddClaim(
                                    new Claim("City", user.City,ClaimValueTypes.String,"Internal")
                                );
                        }
                    }
                }
            }

            return principal;
        }
    }
}
