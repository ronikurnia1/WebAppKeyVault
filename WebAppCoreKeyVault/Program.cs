using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Security.Cryptography.X509Certificates;

namespace WebAppCoreKeyVault
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args).ConfigureAppConfiguration((context, config) =>
            {
                var configBuild = config.Build();
                var keyVaultEndpoint = new Uri(configBuild["ServicePrinciple:KeyVaultEndpoint"]);
                var credential = GetCredential(AuthType.Certificate, configBuild);
                config.AddAzureKeyVault(keyVaultEndpoint, credential);
                //config.AddAzureKeyVault(keyVaultEndpoint, new DefaultAzureCredential());
            }).ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
            });



        private static TokenCredential GetCredential(AuthType authType, IConfigurationRoot config)
        {
            var tenantId = config["ServicePrinciple:TenantId"];
            var appId = config["ServicePrinciple:AppId"];
            var appSecret = config["ServicePrinciple:AppSecret"];
            var certThumbprint = config["ServicePrinciple:CertThumbprint"];

            if (authType == AuthType.Certificate)
            {
                using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbprint, false);
                store.Close();
                return new ClientCertificateCredential(tenantId, appId, certs[0]);
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
