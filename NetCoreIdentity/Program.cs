using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppIdentityDbContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});


#region CookieAuthenticationOptions

CookieBuilder cookieBuilder = new CookieBuilder()
{
    Name = "MyCookie",
    HttpOnly = true,
    Expiration = TimeSpan.FromDays(30),
    //SameSite = SameSiteMode.Strict  => Bankacýlýk gibi hassas uygulamalarda kullanýlabilir. google.com da giriþ yapýnca destek.google.com da da giriþ yapmamýzý ister. Bkz:csrf
    SameSite = SameSiteMode.Lax,
    SecurePolicy = CookieSecurePolicy.SameAsRequest

}; // CookieBuilder

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.Cookie = cookieBuilder;
    opt.LoginPath = new PathString("/Account/Login");
    //opt.LogoutPath = new PathString("/Account/Logout");
    //opt.AccessDeniedPath = new PathString("/Account/AccessDenied");
    opt.SlidingExpiration = true;
});

#endregion


#region IdentityServer4
builder.Services.AddIdentity<AppUser, IdentityRole>(opt =>
    {

        opt.User.RequireUniqueEmail = true;
        opt.User.AllowedUserNameCharacters = "abcçdefgðhiýjklmnoöpqrsþtuüvwxyzABCÇDEFGHIÝJKLMNOÖPQRSÞTUÜVWXYZ0123456789-._";


        opt.Password.RequiredLength = 4;
        opt.Password.RequireNonAlphanumeric = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireUppercase = false;
        opt.Password.RequireDigit = false;
    })
    .AddPasswordValidator<CustomPasswordValidator>()
    .AddEntityFrameworkStores<AppIdentityDbContext>();
#endregion



builder.Services.AddMvc();

var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseStatusCodePages();

app.UseStaticFiles();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.UseAuthentication();



app.Run();

