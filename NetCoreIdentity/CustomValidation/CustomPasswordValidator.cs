using Microsoft.AspNetCore.Identity;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.CustomValidation
{
    public class CustomPasswordValidator : IPasswordValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string password)
        {
            List<IdentityError> errors = new();
            if (password.ToLower().Contains(user.UserName.ToLower()))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContainsUserName",
                    Description = "Parola kullanıcı adı içeremez!"
                });
            }

            if (password.ToLower().Contains("12345"))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContains12345",
                    Description = "Parola ardışık değerler içeremez!"
                });
            }

            if (password.ToLower().Contains(user.Email.ToLower()))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordContainsEmail",
                    Description = "Parola e-posta adresi içeremez!"
                });
            }


            if (errors.Count > 0)
            {
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }
            else
            {
                return Task.FromResult(IdentityResult.Success);
            }

        }
    }
}
