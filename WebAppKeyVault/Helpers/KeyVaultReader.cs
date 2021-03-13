using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace WebAppKeyVault.Helpers
{
    public class KeyVaultReader
    {
        private static readonly string keyVaultEndpoint = ConfigurationManager.AppSettings["KeyValutEndpoint"];
        private static readonly string tenantId = ConfigurationManager.AppSettings["TenantId"];
        private static readonly string appId = ConfigurationManager.AppSettings["AppId"];
        private static readonly string appSecret = ConfigurationManager.AppSettings["AppSecret"];
        private static readonly string certThumbprint = ConfigurationManager.AppSettings["CertThumbprint"];

        public static async Task<string> ReadSecret(string keyName)
        {
            var credential = GetCredential(AuthType.Certificate);
            var secretClient = new SecretClient(new Uri(keyVaultEndpoint), credential);
            KeyVaultSecret keyVaultSecret = await secretClient.GetSecretAsync(keyName);
            return keyVaultSecret.Value;
        }


        public static async Task<IDictionary<string, string>> ReadSecrets(IEnumerable<string> keyNames)
        {
            var credential = GetCredential(AuthType.Certificate);
            var secretClient = new SecretClient(new Uri(keyVaultEndpoint), credential);

            var secrets = new Dictionary<string, string>();
            foreach (var keyName in keyNames)
            {
                KeyVaultSecret keyVaultSecret = await secretClient.GetSecretAsync(keyName);
                secrets.Add(keyName, keyVaultSecret.Value);
            }
            return secrets;
        }


        private static TokenCredential GetCredential(AuthType authType)
        {
            if (authType == AuthType.Certificate)
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.OpenExistingOnly);
                    var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, false);
                    store.Close();
                    return new ClientCertificateCredential(tenantId, appId, certs[0]);
                }
            }
            else
            {
                return new ClientSecretCredential(tenantId, appId, appSecret);
            }
        }

        private enum AuthType
        {
            Secret = 0,
            Certificate = 1
        }
    }
}