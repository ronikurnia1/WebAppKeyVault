using System.Configuration;
using System.Data.SqlClient;
using System.Security;
using System.Threading.Tasks;
using System.Web.Mvc;
using WebAppKeyVault.Helpers;

namespace WebAppKeyVault.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> About()
        {
            var dbUserName = "DbUserName";
            var dbPassword = "DbPassword";

            var secrets = await KeyVaultReader.ReadSecrets(new string[] { dbUserName, dbPassword });
            var dbUserNameValue = secrets[dbUserName];
            var dbPasswordValue = secrets[dbPassword];

            ViewBag.Message = $"Credential information";
            ViewBag.UserName = $"{dbUserNameValue}";
            ViewBag.Password = $"{dbPasswordValue}";

            // Modify credential of ConnectionString
            var connString = ConfigurationManager.ConnectionStrings["DbConnectionString"].ConnectionString;
            var conn = new SqlConnection(connString);

            var securePassword = new SecureString();
            foreach (char character in dbPasswordValue)
            {
                securePassword.AppendChar(character);
            }
            securePassword.MakeReadOnly();
            conn.Credential = new SqlCredential(dbUserNameValue, securePassword);

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }
    }
}