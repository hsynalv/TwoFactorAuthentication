using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetCoreIdentity.ClaimProvider;
using NetCoreIdentity.CustomValidation;
using NetCoreIdentity.Extensions;
using NetCoreIdentity.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureAddTransit();
builder.Services.ConfigureSqlContext(builder.Configuration);
builder.Services.ConfigureAddAuthorization();
builder.Services.ConfigureAddIdentityServer4();
builder.Services.ConfigureCookieAuthenticationOptions();
builder.Services.ConfigureAddScoped();


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

