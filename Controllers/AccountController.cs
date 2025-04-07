using System.Security.Cryptography;
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

    // Keycloak configuration values – adjust these values accordingly.
    private readonly string clientId = "ssd";
    private readonly string clientSecret = "6yteYiURIPXLqfzwYh9HHIktW34TYe5t";
    private readonly string callbackUrl = "https://localhost:7235/account/callback";

    // Hard-coded Keycloak endpoints (for demonstration only; production apps should load these from configuration).
    private readonly string authorizationEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/auth";
    private readonly string tokenEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/token";
    private readonly string userInfoEndpoint = "http://localhost:8080/realms/master/protocol/openid-connect/userinfo";
    private readonly string jwksUri = "http://localhost:8080/realms/master/protocol/openid-connect/certs";

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

        var tokenResult = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();

        // Store the token and user info in the session or cookies
        HttpContext.Session.SetString("AccessToken", tokenResult.access_token);
        HttpContext.Session.SetString("IdToken", tokenResult.id_token);

        // Optionally fetch user info
        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {tokenResult.access_token}");
        var userInfoResponse = await httpClient.GetAsync(userInfoEndpoint);
        var userInfo = await userInfoResponse.Content.ReadAsStringAsync();

        // Store the user info in the session or cookies as needed
        HttpContext.Session.SetString("UserInfo", userInfo);

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