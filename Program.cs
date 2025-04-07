var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();

// Configure Keycloak authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies"; // Default cookies for session
        options.DefaultChallengeScheme = "oidc"; // Default to OpenID Connect
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        options.Authority = "https://<your-keycloak-domain>/realms/<realm-name>";
        options.ClientId = "ssd";
        options.ClientSecret = "6yteYiURIPXLqfzwYh9HHIktW34TYe5t";  // Only if you have a client secret (otherwise use public clients)
        options.ResponseType = "code"; // For authorization code flow
        options.SaveTokens = true; // Store tokens in the session
        options.Scope.Add("openid");  // Default OpenID scope
        options.Scope.Add("profile"); // Optional: Add other scopes like profile, email, etc.

        // Redirect URI after login
        options.CallbackPath = "/signin-oidc";
    
        // Ensure the cookies are set properly
        options.SignedOutCallbackPath = "/signout-callback-oidc";
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