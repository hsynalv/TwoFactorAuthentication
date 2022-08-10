using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppIdentityDbContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

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
    .AddEntityFrameworkStores<AppIdentityDbContext>();

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

