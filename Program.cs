using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

//session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true; 
});

// Keycloak authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID");
        options.Authority = "http://localhost:8080/realms/master";
        options.ClientId = "ssd";
        options.ClientSecret = "6yteYiURIPXLqfzwYh9HHIktW34TYe5t";
        options.ResponseType = "code"; // For authorization code flow
        options.SaveTokens = true; // Store tokens in the session
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        options.RequireHttpsMetadata = false;
    });

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseSession();

app.UseAuthentication(); 
app.UseAuthorization();

app.MapStaticAssets();

// Map routes for MVC
app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

Env.Load();

app.Run();