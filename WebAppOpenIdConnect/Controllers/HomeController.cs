using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
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

        public HomeController(ILogger<HomeController> logger, IConfiguration config)
        {
            _logger = logger;
            this.config = config;
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task< IActionResult> Privacy()
        {
            var secretName = "DbPassword";
            var credential = new DefaultAzureCredential();
            var secretClient = new SecretClient(new Uri(config["KeyVaultEndpoint"]), credential);
            KeyVaultSecret keyVaultSecret = await secretClient.GetSecretAsync(secretName);
            ViewBag.KeyVaultSecret = keyVaultSecret.Value;
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
