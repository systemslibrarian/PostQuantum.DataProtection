// A minimal-API ASP.NET Core sample that protects cookies and antiforgery tokens with the
// PostQuantum.DataProtection ML-KEM-768 + AES-256-GCM hybrid envelope.
//
// What it demonstrates end-to-end:
//   - One-line wiring of PostQuantum.KeyManagement (the classical KEK) and PostQuantum.DataProtection
//     (the post-quantum / hybrid Data Protection wrap).
//   - Real cookie roundtrip protected by the PQ envelope. Open the printed URL in two browsers; the
//     second visit reads back the cookie that the first visit set.
//   - Real antiforgery-token roundtrip. POST /form with the token rendered on GET /; the token is
//     protected by a Data Protection key whose XML representation is itself wrapped in a pqEnvelope.
//   - Inspect-on-disk story. After running, look at keys/data-protection/key-*.xml — every key file
//     contains a <pqEnvelope> element. Look at keys/pq-keystore.txt — the ML-KEM keypair lives
//     there with the secret key wrapped under the host KEK.

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PostQuantum.DataProtection.Hybrid;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// ── 1. The classical key-management layer ────────────────────────────────────────────────────────
// PostQuantum.KeyManagement provides the IContentKeyProvider that PostQuantum.DataProtection's
// classical layer uses to envelope-encrypt the long-lived ML-KEM secret key.
builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException(
            "Set KeyManagement:Passphrase in appsettings.Development.json (or a secret manager in production).");
    options.WorkFactor = KekWorkFactor.Interactive;
    options.KeyringPath = "keys/host-keyring.bin";
});

// ── 2. ASP.NET Core Data Protection with post-quantum key wrapping ───────────────────────────────
// One line. Every Data Protection key — cookies, antiforgery, session tickets, any IDataProtector
// payload — is now persisted under a hybrid ML-KEM-768 + AES-256-GCM envelope.
builder.Services
    .AddDataProtection()
    .SetApplicationName("PostQuantum.DataProtection.Sample")
    .PersistKeysToFileSystem(new DirectoryInfo("keys/data-protection"))
    .ProtectKeysWithPostQuantum(options =>
    {
        options.KeyStorePath = "keys/pq-keystore.txt";
        options.Mode = HybridKemMode.Hybrid;  // production default
    });

// ── 3. Realistic consumers: cookie auth + antiforgery ────────────────────────────────────────────
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = ".pq.sample.session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-Token");
builder.Services.AddAuthorization();

WebApplication app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ── 4. Endpoints ─────────────────────────────────────────────────────────────────────────────────
app.MapGet("/", (HttpContext ctx, IAntiforgery antiforgery) =>
{
    AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(ctx);
    string? user = ctx.User.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : null;

    string body = $$"""
<!doctype html>
<meta charset="utf-8">
<title>PostQuantum.DataProtection sample</title>
<style>body{font-family:system-ui;max-width:42em;margin:3em auto;line-height:1.55;color:#1c1c1c}
       code{background:#f0f0f0;padding:0 .2em}</style>
<h1>PostQuantum.DataProtection sample</h1>
<p>This page is rendered by an ASP.NET Core host whose Data Protection keys are wrapped in an
   <strong>ML-KEM-768 + AES-256-GCM hybrid envelope</strong> via
   <code>ProtectKeysWithPostQuantum(...)</code>. Inspect
   <code>keys/data-protection/key-*.xml</code> on disk to see the <code>pqEnvelope</code> element.</p>
<p>Current user: <strong>{{(user ?? "(anonymous)")}}</strong></p>
<form method="post" action="/sign-in">
  <input type="hidden" name="{{tokens.FormFieldName}}" value="{{tokens.RequestToken}}" />
  <input name="username" placeholder="username" required />
  <button>Sign in (sets a PQ-protected cookie)</button>
</form>
<form method="post" action="/sign-out" style="margin-top:1em">
  <input type="hidden" name="{{tokens.FormFieldName}}" value="{{tokens.RequestToken}}" />
  <button>Sign out</button>
</form>
<p style="margin-top:2em">
  <a href="/health">/health</a> · <a href="/protect-demo">/protect-demo</a> ·
  <a href="/rotate-pq">POST /rotate-pq</a>
</p>
""";

    ctx.Response.ContentType = "text/html; charset=utf-8";
    return Results.Text(body, "text/html");
});

app.MapPost("/sign-in", async (HttpContext ctx, IAntiforgery antiforgery, [FromForm] string username) =>
{
    await antiforgery.ValidateRequestAsync(ctx);

    var claims = new[] { new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, username) };
    var identity = new System.Security.Claims.ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new System.Security.Claims.ClaimsPrincipal(identity);

    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    return Results.Redirect("/");
}).DisableAntiforgery(); // we validate explicitly above so we can read the form first

app.MapPost("/sign-out", async (HttpContext ctx, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(ctx);
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
}).DisableAntiforgery();

// A direct IDataProtector roundtrip so the sample shows that arbitrary payloads work too.
app.MapGet("/protect-demo", (IDataProtectionProvider dp) =>
{
    IDataProtector protector = dp.CreateProtector("PostQuantum.DataProtection.Sample.Demo");
    string plaintext = $"hello at {DateTimeOffset.UtcNow:O}";
    string protectedToken = protector.Protect(plaintext);
    string roundtripped = protector.Unprotect(protectedToken);

    return Results.Ok(new
    {
        plaintext,
        protectedToken,
        roundtripped,
        note = "The Data Protection key that produced this token is itself wrapped in a pqEnvelope on disk.",
    });
});

// Force a PQ keypair rotation. In production this is an admin endpoint; here it is open so the
// sample is easy to exercise.
app.MapPost("/rotate-pq", async (PostQuantum.DataProtection.Keys.PostQuantumKeyManager pq) =>
{
    string newId = await pq.RotateAsync();
    return Results.Ok(new { activeKeyId = newId });
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.Run();
