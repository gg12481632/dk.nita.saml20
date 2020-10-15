using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Http;

namespace WebApi.Controllers
{
    public class ValuesController : ApiController
    {
        // GET api/values
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        public string Get(string id)
        {


            StringBuilder sb = new StringBuilder();
            sb.AppendLine("");

            string thumbprint = id;

            CertificateCheck(thumbprint, sb);

            sb.AppendLine("");
            string result = sb.ToString();
            return result;
        }


        static void CertificateCheck(string thumbprint, StringBuilder sb)
        {

            X509Certificate2 Certificate = null;
            // Read the certificate from the store
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                // Try to find the certificate
                // based on its common name
                X509Certificate2Collection Results =
                store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (Results.Count == 0)
                {
                    sb.AppendLine("Certificate not found, thumbprint=" + thumbprint);
                    return;
                }
                else
                {
                    sb.AppendLine("ResultsCount=" + Results.Count);
                    Certificate = Results[0];
                    sb.AppendLine("Before GetRSAPublicKey");
                    RSA rsaPublic = Certificate.GetRSAPublicKey();
                    sb.AppendLine("After GetRSAPublicKey");
                    sb.AppendLine("Before GetRSAPrivateKey");
                    RSA rsaPrivate = Certificate.GetRSAPrivateKey();
                    sb.AppendLine("After GetRSAPrivateKey");
                }
            }
            catch (Exception e)
            {
                sb.AppendLine(e.ToString());
            }
            finally
            {
                store.Close();
            }
        }

    }
}
