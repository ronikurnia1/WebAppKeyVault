using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System.Collections.Generic;
using System.Configuration;
using System.Threading;
using System.Threading.Tasks;

namespace WebAppKeyVault.Helpers
{
    public class KeyVaultReader
    {
        public static async Task<string> ReadSecret(string keyName)
        {
            var keyVaultEndpoint = ConfigurationManager.AppSettings["KeyValutEndpoint"];
            var tenantId = ConfigurationManager.AppSettings["TenantId"];
            var appId = ConfigurationManager.AppSettings["AppId"];
            var appSecret = ConfigurationManager.AppSettings["AppSecret"];

            var tokenConnectionString = $"RunAs=App;AppId={appId};TenantId={tenantId};AppKey={appSecret}";
            var azureServiceTokenProvider = new AzureServiceTokenProvider(tokenConnectionString);
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

            var secret = await keyVaultClient.GetSecretAsync(keyVaultEndpoint, keyName, CancellationToken.None);
            return secret.Value;
        }


        public static async Task<IDictionary<string, string>> ReadSecrets(IEnumerable<string> keyNames)
        {
            var secrets = new Dictionary<string, string>();

            var keyVaultEndpoint = ConfigurationManager.AppSettings["KeyValutEndpoint"];
            var tenantId = ConfigurationManager.AppSettings["TenantId"];
            var appId = ConfigurationManager.AppSettings["AppId"];
            var appSecret = ConfigurationManager.AppSettings["AppSecret"];

            var tokenConnectionString = $"RunAs=App;AppId={appId};TenantId={tenantId};AppKey={appSecret}";
            var azureServiceTokenProvider = new AzureServiceTokenProvider(tokenConnectionString);
            var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

            foreach(var keyName in keyNames)
            {
                var secret = await keyVaultClient.GetSecretAsync(keyVaultEndpoint, keyName, CancellationToken.None);
                secrets.Add(keyName, secret.Value);
            }

            return secrets;
        }


    }
}