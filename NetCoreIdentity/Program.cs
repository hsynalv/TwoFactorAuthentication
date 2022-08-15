using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppIdentityDbContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});



#region IdentityServer4  1. s�rada olmal�
builder.Services.AddIdentity<AppUser, IdentityRole>(opt =>
    {

        opt.User.RequireUniqueEmail = true;
        opt.User.AllowedUserNameCharacters = "abc�defg�hi�jklmno�pqrs�tu�vwxyzABC�DEFGHI�JKLMNO�PQRS�TU�VWXYZ0123456789-._";


        opt.Password.RequiredLength = 4;
        opt.Password.RequireNonAlphanumeric = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireUppercase = false;
        opt.Password.RequireDigit = false;
    })
    .AddPasswordValidator<CustomPasswordValidator>()
    .AddEntityFrameworkStores<AppIdentityDbContext>()
    .AddDefaultTokenProviders();
#endregion

#region CookieAuthenticationOptions 2. s�rada olmal�.

CookieBuilder cookieBuilder = new CookieBuilder()
{
    Name = "MyCookie",
    HttpOnly = true,
    //SameSite = SameSiteMode.Strict  => Bankac�l�k gibi hassas uygulamalarda kullan�labilir. google.com da giri� yap�nca destek.google.com da da giri� yapmam�z� ister. Bkz:csrf
    SameSite = SameSiteMode.Lax,
    SecurePolicy = CookieSecurePolicy.SameAsRequest

}; // CookieBuilder

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.Cookie = cookieBuilder;
    opt.LoginPath = new PathString("/Home/Login");
    opt.ExpireTimeSpan = TimeSpan.FromDays(30);
    opt.LogoutPath = new PathString("/Member/LogOut");
    //opt.AccessDeniedPath = new PathString("/Account/AccessDenied");
    opt.SlidingExpiration = true;
    opt.AccessDeniedPath = new PathString("/Member/AccessDenied");
});

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

