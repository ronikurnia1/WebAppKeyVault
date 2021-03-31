using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using WebApp_OpenIDConnect.Models;

namespace WebApp_OpenIDConnect.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration config;
        private readonly IHttpClientFactory clientFactory;

        public HomeController(ILogger<HomeController> logger,
            IConfiguration config, IHttpClientFactory clientFactory)
        {
            _logger = logger;
            this.config = config;
            this.clientFactory = clientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Privacy()
        {
            string secretName = "DbPassword";
            var credential = new DefaultAzureCredential();
            var secretClient = new SecretClient(new Uri(config["KeyVaultEndpoint"]), credential);
            KeyVaultSecret keyVaultSecret = await secretClient.GetSecretAsync(secretName);
            ViewBag.KeyVaultSecret = keyVaultSecret.Value;
            return View();
        }

        public async Task<IActionResult> About()
        {

            // Get token
            var tokenRequestContext = new TokenRequestContext(new[] { "api://a3cad856-d73c-40bc-b082-64982a3e55ac/KeyVault" });

            var tokenCredential = new DefaultAzureCredential(new DefaultAzureCredentialOptions()
            {
                InteractiveBrowserTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47",
                SharedTokenCacheTenantId = "common",
                SharedTokenCacheUsername = User.Identity.Name,
                ExcludeEnvironmentCredential = true,
                ExcludeManagedIdentityCredential = true,
                ExcludeAzureCliCredential = true,
                ExcludeVisualStudioCodeCredential = true,
            });

            //var credOption = new SharedTokenCacheCredentialOptions();
            //credOption.TenantId = User.Claims.FirstOrDefault(t => t.Type == "http://schemas.microsoft.com/identity/claims/tenantid").Value;
            //credOption.Username = User.Identity.Name;
            //var sharedCredential = new SharedTokenCacheCredential(credOption);

            var token = await tokenCredential.GetTokenAsync(tokenRequestContext, CancellationToken.None);
            //var token = await new SharedTokenCacheCredential(credOption).GetTokenAsync(tokenRequestContext, CancellationToken.None);
            // Get Key Vault secret
            var secretName = "DbPassword";
            var httpClient = clientFactory.CreateClient();
            httpClient.BaseAddress = new Uri(config["ServicePrinciple:KeyVaultEndpoint"]);
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            var requestKeyVault = new HttpRequestMessage(HttpMethod.Get, $"secrets/{secretName}?api-version=7.0");
            var keyVaultResponse = await httpClient.SendAsync(requestKeyVault);
            if (keyVaultResponse.IsSuccessStatusCode)
            {
                var message = await keyVaultResponse.Content.ReadAsStringAsync();
                ViewBag.DbPassword = JsonSerializer.Deserialize<KeyVaultResponse>(message).value;
            }
            else
            {
                ViewBag.DbPassword = keyVaultResponse.ReasonPhrase;
            }
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }

    internal class KeyVaultResponse
    {
        public string value { get; set; }
    }

}
