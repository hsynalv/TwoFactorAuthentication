using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.ClaimProvider;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Extensions;
using NetCoreIdentity.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureSqlContext(builder.Configuration);
builder.Services.ConfigureAddAuthorization();
builder.Services.ConfigureAddIdentityServer4();
builder.Services.ConfigureCookieAuthenticationOptions();
builder.Services.ConfigureAddScoped();






#region IdentityServer4  1. sýrada olmalý

#endregion

#region CookieAuthenticationOptions 2. sýrada olmalý.

// CookieBuilder



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
app.UseAuthorization();


app.Run();

