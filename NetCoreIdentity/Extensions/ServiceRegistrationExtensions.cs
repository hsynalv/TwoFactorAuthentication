﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Models;

namespace NetCoreIdentity.Extensions
{
    public static class ServiceRegistrationExtensions
    {
        public static void ConfigureSqlContext(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<AppIdentityDbContext>(opt =>
            {
                opt.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
            });
        }

        public static void ConfigureAddAuthorization(this IServiceCollection services)
        {
            services.AddAuthorization(opt =>
            {
                opt.AddPolicy("SamsunPolicy", policy =>
                {
                    policy.RequireClaim("City", "Samsun");
                });
            });
        }

        public static void ConfigureAddIdentityServer4(this IServiceCollection services)
        {
            services.AddIdentity<AppUser, IdentityRole>(opt =>
                {

                    opt.User.RequireUniqueEmail = true;
                    opt.User.AllowedUserNameCharacters = "abcçdefgğhiıjklmnoöpqrsştuüvwxyzABCÇDEFGHIİJKLMNOÖPQRSŞTUÜVWXYZ0123456789-._";


                    opt.Password.RequiredLength = 4;
                    opt.Password.RequireNonAlphanumeric = false;
                    opt.Password.RequireLowercase = false;
                    opt.Password.RequireUppercase = false;
                    opt.Password.RequireDigit = false;
                })
                .AddPasswordValidator<CustomPasswordValidator>()
                .AddEntityFrameworkStores<AppIdentityDbContext>()
                .AddDefaultTokenProviders();
        }

        public static void ConfigureCookieAuthenticationOptions(this IServiceCollection services)
        {
            CookieBuilder cookieBuilder = new CookieBuilder()
            {
                Name = "MyCookie",
                HttpOnly = true,
                //SameSite = SameSiteMode.Strict  => Bankacılık gibi hassas uygulamalarda kullanılabilir. google.com da giriş yapınca destek.google.com da da giriş yapmamızı ister. Bkz:csrf
                SameSite = SameSiteMode.Lax,
                SecurePolicy = CookieSecurePolicy.SameAsRequest

            };

            services.ConfigureApplicationCookie(opt =>
            {
                opt.Cookie = cookieBuilder;
                opt.LoginPath = new PathString("/Home/Login");
                opt.ExpireTimeSpan = TimeSpan.FromDays(30);
                opt.LogoutPath = new PathString("/Member/LogOut");
                opt.SlidingExpiration = true;
                opt.AccessDeniedPath = new PathString("/Member/AccessDenied");
            });
        }

        public static void ConfigureAddScoped(this IServiceCollection services)
        {
            services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();
        }
    }
}
