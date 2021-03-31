using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WebApp.Helpers
{
    public class ClientAssetionGenerator
    {

        private static string thumbPrint = ConfigurationManager.AppSettings["CertificateThumbprint"];
        private static string tenantId = ConfigurationManager.AppSettings["TenantId"];
        private static string clientId = ConfigurationManager.AppSettings["AppId"];



        public static string GetSignedClientAssertion()
        {
            //Signing with SHA-256
            X509Certificate2 certificate = GetCertificate(thumbPrint);
            var privateKeyXmlParams = certificate.PrivateKey.ToXmlString(true);

            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKeyXmlParams);

            //alg represents the desired signing algorithm, which is SHA-256 in this case
            //kid represents the certificate thumbprint
            var header = new Dictionary<string, string>()
            {
              { "alg", "RS256"},
                {"typ", "JWT"},
                {"x5t", Encode(certificate.GetCertHash())}
            };

            string token = Encode(Encoding.UTF8.GetBytes(JObject.FromObject(header).ToString())) + "." + Encode(Encoding.UTF8.GetBytes(JObject.FromObject(GetClaims(tenantId, clientId)).ToString()));

            string signature = Encode(rsa.SignData(Encoding.UTF8.GetBytes(token), SHA256.Create()));

            string signedClientAssertion = string.Concat(token, ".", signature);

            return signedClientAssertion;
        }


        private static IDictionary<string, string> GetClaims(string tenantId, string clientId)
        {
            //aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
            string aud = $"https://login.microsoftonline.com/{tenantId}/v2.0";

            const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
            DateTime validFrom = DateTime.UtcNow;
            var nbf = ConvertToTimeT(validFrom);
            var exp = ConvertToTimeT(validFrom + TimeSpan.FromSeconds(JwtToAadLifetimeInSeconds));

            return new Dictionary<string, string>()
           {
                { "aud", aud },
                { "exp", exp.ToString() },
                { "iss", clientId },
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", nbf.ToString() },
                { "sub", clientId }
            };
        }

        private static string Encode(byte[] arg)
        {
            char Base64PadCharacter = '=';
            char Base64Character62 = '+';
            char Base64Character63 = '/';
            char Base64UrlCharacter62 = '-';
            char Base64UrlCharacter63 = '_';

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }


        private static long ConvertToTimeT(DateTime time)
        {
            var startTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            TimeSpan diff = time - startTime;
            return (long)diff.TotalSeconds;
        }

        private static X509Certificate2 GetCertificate(string certThumbPrint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly);
            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbPrint, false);
            store.Close();
            return certs[0];
        }


    }
}