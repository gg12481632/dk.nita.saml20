using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificateReader
{
    class Program
    {
        // returns report
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


        static void Main(string[] args)
        {
            if(args.Count()!=1)
            {
                Console.WriteLine("Usage: CertificateReader <thumbprint>");
                return;
            }

            StringBuilder sb = new StringBuilder();

            string thumbprint = args[0];

            CertificateCheck(thumbprint,sb);
            Console.WriteLine(sb.ToString());

        }
    }
}
