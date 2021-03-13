using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security;
using WebAppCoreKeyVault.Models;

namespace WebAppCoreKeyVault.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfigurationRoot config;

        public HomeController(ILogger<HomeController> logger, IConfigurationRoot config)
        {
            _logger = logger;
            this.config = config;
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

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
