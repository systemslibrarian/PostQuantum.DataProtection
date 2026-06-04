// Blazor Server host whose Data Protection keys — the same keys that sign the circuit reconnect
// token, the auth cookie, and any IDataProtector payload — are wrapped under PostQuantum.DataProtection.

using Blazor.Sample.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = ".pq.blazor.sample";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.LoginPath = "/login";
    });
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

// PQ data protection — same one-liner as in AspNetCore.Sample.
builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? "blazor-sample-passphrase-not-secret";
    o.WorkFactor = KekWorkFactor.LowMemory;
    o.KeyringPath = "keys/host-keyring.bin";
});

builder.Services
    .AddDataProtection()
    .SetApplicationName("PostQuantum.DataProtection.Blazor.Sample")
    .PersistKeysToFileSystem(new DirectoryInfo("keys/data-protection"))
    .ProtectKeysWithPostQuantum(o =>
    {
        o.KeyStorePath = "keys/pq-keystore.txt";
        o.Mode = HybridKemMode.Hybrid;
    });

WebApplication app = builder.Build();

app.UseStaticFiles();
app.UseAntiforgery();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

// Tiny login form so the cookie auth roundtrip is real, not theoretical.
app.MapPost("/login/sign-in", async (HttpContext ctx, string username) =>
{
    var claims = new[] { new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, username) };
    var identity = new System.Security.Claims.ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new System.Security.Claims.ClaimsPrincipal(identity));
    ctx.Response.Redirect("/");
});

app.MapPost("/login/sign-out", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    ctx.Response.Redirect("/");
});

app.Run();
