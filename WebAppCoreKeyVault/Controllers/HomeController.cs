using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using System.Security;
using System.Text.Json;
using System.Threading.Tasks;
using WebAppCoreKeyVault.Models;

namespace WebAppCoreKeyVault.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfigurationRoot config;
        private readonly IHttpClientFactory httpClientFactory;

        public HomeController(ILogger<HomeController> logger,
            IConfigurationRoot config, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            this.config = config;
            this.httpClientFactory = httpClientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            config.Reload();
            ViewBag.DbPassword = config["DbPassword"];
            ViewBag.DbUserName = config["DbUserName"];

            // Modify credential of ConnectionString
            var connString = config.GetConnectionString("DbConnectionString");
            var conn = new SqlConnection(connString);

            var securePassword = new SecureString();
            foreach (char character in ViewBag.DbPassword)
            {
                securePassword.AppendChar(character);
            }
            securePassword.MakeReadOnly();
            conn.Credential = new SqlCredential(ViewBag.DbUserName, securePassword);

            return View();
        }


        public async Task<IActionResult> About()
        {
            // Get token
            var httpClient = httpClientFactory.CreateClient();
            httpClient.BaseAddress = new System.Uri("https://login.microsoftonline.com/");
            var requestToken = new HttpRequestMessage(HttpMethod.Post, config["ServicePrinciple:TenantId"] + "/oauth2/token");
            var content = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", config["ServicePrinciple:AppId"]),
                new KeyValuePair<string, string>("client_secret", config["ServicePrinciple:AppSecret"]),
                new KeyValuePair<string, string>("resource", "https://vault.azure.net")
            };
            requestToken.Content = new FormUrlEncodedContent(content);
            var tokenResponse = await httpClient.SendAsync(requestToken);
            if (tokenResponse.IsSuccessStatusCode)
            {
                // Get Key Vault secret
                var secretName = "DbPassword";
                var message = await tokenResponse.Content.ReadAsStringAsync();
                var accessToken = JsonSerializer.Deserialize<AuthResponse>(message).access_token;
                httpClient = httpClientFactory.CreateClient();
                httpClient.BaseAddress = new System.Uri(config["ServicePrinciple:KeyVaultEndpoint"]);
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                var requestKeyVault = new HttpRequestMessage(HttpMethod.Get, $"secrets/{secretName}?api-version=7.0");
                var keyVaultResponse = await httpClient.SendAsync(requestKeyVault);
                if (keyVaultResponse.IsSuccessStatusCode)
                {
                    message = await keyVaultResponse.Content.ReadAsStringAsync();
                    ViewBag.DbPassword = JsonSerializer.Deserialize<KeyVaultSecret>(message).value;
                }
                else
                {
                    ViewBag.DbPassword = keyVaultResponse.ReasonPhrase;
                }
            }
            else
            {
                ViewBag.DbPassword = tokenResponse.ReasonPhrase;
            }
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }


    internal class AuthResponse
    {
        public string access_token { get; set; }
    }

    internal class KeyVaultSecret
    {
        public string value { get; set; }
    }
}
