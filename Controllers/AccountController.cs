using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using SSD_OpenID.Models;

namespace SSD_OpenID.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    // In-memory cache to store code_verifiers keyed by state.
    private static readonly Dictionary<string, string> _cache = new();

    private readonly string clientId = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID");
    private readonly string clientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET");
    private readonly string callbackUrl = Environment.GetEnvironmentVariable("KEYCLOAK_CALLBACK_URL");

    private readonly string authorizationEndpoint = Environment.GetEnvironmentVariable("KEYCLOAK_AUTH_ENDPOINT");
    private readonly string tokenEndpoint = Environment.GetEnvironmentVariable("KEYCLOAK_TOKEN_ENDPOINT");
    private readonly string userInfoEndpoint = Environment.GetEnvironmentVariable("KEYCLOAK_USERINFO_ENDPOINT");
    private readonly string jwksUri = Environment.GetEnvironmentVariable("KEYCLOAK_JWKS_URI");


    // GET /login endpoint
    [HttpGet("login")]
    public IActionResult Login()
    {
        // Generate secure random strings for state and codeVerifier.
        string state = GenerateRandomString();
        string codeVerifier = GenerateRandomString();

        // Store the codeVerifier in cache using state as the key.
        _cache[state] = codeVerifier;

        // Build the authorization URL with required parameters.
        var parameters = new Dictionary<string, string>
        {
            { "client_id", clientId },
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", callbackUrl },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "plain" },
            { "code_challenge", codeVerifier }
        };

        string authorizationUri = QueryHelpers.AddQueryString(authorizationEndpoint, parameters);

        // Redirect the client to Keycloak for authentication.
        return Redirect(authorizationUri);
    }

    // GET /callback endpoint
    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string state, [FromQuery] string code)
    {
        if (string.IsNullOrEmpty(state) || string.IsNullOrEmpty(code))
        {
            return BadRequest("Missing state or code parameter.");
        }

        if (!_cache.TryGetValue(state, out var codeVerifier))
        {
            return BadRequest("Invalid or expired state.");
        }

        var tokenParams = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", callbackUrl },
            { "code_verifier", codeVerifier },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };

        using var httpClient = new HttpClient();
        var tokenResponse = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(tokenParams));
        if (!tokenResponse.IsSuccessStatusCode)
        {
            return BadRequest("Error exchanging code for token.");
        }

        TokenResponse tokenResult = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();

        // Store the token and user info in the session or cookies
        HttpContext.Session.SetString("AccessToken", tokenResult.access_token);
        HttpContext.Session.SetString("IdToken", tokenResult.id_token);

        // Optionally fetch user info
        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {tokenResult.access_token}");
        var userInfoResponse = await httpClient.GetAsync(userInfoEndpoint);
        var userInfo = await userInfoResponse.Content.ReadAsStringAsync();

        // Store the user info in the session or cookies as needed
        HttpContext.Session.SetString("UserInfo", userInfo);
        var userInfoJson = JsonDocument.Parse(userInfo);
        var root = userInfoJson.RootElement;
        string sub = root.GetProperty("sub").GetString();
        string username = root.GetProperty("preferred_username").GetString();
        
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, sub),
            new Claim(ClaimTypes.Name, username),
        };
        
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        
        return RedirectToAction("Index", "Home");
    }
    
    [HttpGet("logout")]
    public IActionResult Logout()
    {
        HttpContext.SignOutAsync();
        HttpContext.Session.Clear();
        return RedirectToAction("Index", "Home");
    }

    // Helper method: Generate a secure random string.
    private static string GenerateRandomString(int length = 32)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[length];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}