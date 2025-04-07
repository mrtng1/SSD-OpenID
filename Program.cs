var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();

// Add session support
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // Set session timeout
    options.Cookie.HttpOnly = true;  // Makes session cookie more secure
    options.Cookie.IsEssential = true;  // Make session cookie essential for functionality
});

// Configure Keycloak authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies"; // Default cookies for session
        options.DefaultChallengeScheme = "oidc"; // Default to OpenID Connect
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
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

// Add MVC with controllers
var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

// Enable session middleware
app.UseSession();

// Enable authentication and authorization
app.UseAuthentication();  // Add authentication middleware
app.UseAuthorization();

app.MapStaticAssets();

// Map routes for MVC
app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();