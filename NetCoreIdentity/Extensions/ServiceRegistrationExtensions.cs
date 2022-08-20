using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.AuthorizationHelpers;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Models;
using NetCoreIdentity.TwoFactorServices;

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

                opt.AddPolicy("ViolencePolicy", policy =>
                {
                    policy.RequireClaim("Violence");
                });

                opt.AddPolicy("ExchangePolicy", policy =>
                {
                    policy.AddRequirements(new ExpireDateExchangeRequirement());
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
            services.AddScoped<TwoFactorService>();
            services.AddScoped<EmailSender>();
            services.AddScoped<SmsSender>();

        }

        public static void ConfigureAddTransit(this IServiceCollection services)
        {
            services.AddTransient<IAuthorizationHandler, ExpireDateExchangeHandler>();
        }

        public static void ConfigureExternalLogin(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication()
                .AddFacebook(opt =>
                {
                    opt.AppId = configuration["Authentication:Facebook:AppId"]; 
                    opt.AppSecret = configuration["Authentication:Facebook:AppSecret"];
                })
                .AddGoogle(opt =>
                {
                    opt.ClientId = configuration["Authentication:Google:ClientId"];
                    opt.ClientSecret = configuration["Authentication:Google:ClientSecret"];
                })
                .AddMicrosoftAccount(opt =>
                {
                    opt.ClientId = configuration["Authentication:Microsoft:ClientId"];
                    opt.ClientSecret = configuration["Authentication:Microsoft:ClientSecret"];
                });
        }

        public static void ConfigureTwoFactorOptions(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<TwoFactorOptions>(configuration.GetSection("TwoFactorOptions"));
        }

        public static void ConfigureSession(this IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.Name = "MainSession";
            });
        }
    }
}
