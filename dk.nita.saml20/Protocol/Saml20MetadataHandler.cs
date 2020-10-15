using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using dk.nita.saml20.config;
using Saml2.Properties;
using System.Security.Cryptography.Xml;
using System.Diagnostics;
using Trace = dk.nita.saml20.Utils.Trace;
using System.Security.Cryptography;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// The handler that exposes a metadata endpoint to the other parties of the federation.
    ///     
    /// The handler accepts the following GET parameters :
    /// - encoding : Delivers the Metadata document in the specified encoding. Example: encoding=iso-8859-1 . If the parameter is omitted, the encoding utf-8 is used.
    /// - sign : A boolean parameter specifying whether to sign the metadata document. Example: sign=false. If the parameter is omitted, the document is signed.
    /// </summary>
    public class Saml20MetadataHandler : AbstractEndpointHandler
    {
        #region IHttpHandler Members

        /// <summary>
        /// Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler"/> interface.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpContext"/> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests.</param>
        public override void ProcessRequest(HttpContext context)
        {
            string encoding = context.Request.QueryString["encoding"];
            try
            {
                if (!string.IsNullOrEmpty(encoding))
                    context.Response.ContentEncoding = Encoding.GetEncoding(encoding);
            }
            catch (ArgumentException)
            {
                HandleError(context, string.Format(Resources.UnknownEncoding, encoding));
                return;
            }

            bool sign = true;
            try
            {
                string param = context.Request.QueryString["sign"];                
                if (!string.IsNullOrEmpty(param))
                    sign = Convert.ToBoolean(param);
            } catch(FormatException)
            {
                HandleError(context, Resources.GenericError);
                return;
            }
                        
            context.Response.ContentType = Saml20Constants.METADATA_MIMETYPE;
            context.Response.AddHeader("Content-Disposition", "attachment; filename=\"metadata.xml\"");

            CreateMetadataDocument(context, sign);
            
            context.Response.End();            
        }

        /// <summary>
        /// Gets a value indicating whether this instance is reusable.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if this instance is reusable; otherwise, <c>false</c>.
        /// </value>
        public new bool IsReusable
        {
            get { return false; }
        }

        #endregion

        private void CreateMetadataDocument(HttpContext context, bool sign)
        {
            MyLog.Write("CreateMetadataDocument");

            SAML20FederationConfig configuration = SAML20FederationConfig.GetConfig();

            KeyInfo keyinfo = new KeyInfo();

            FederationConfig federationConfig = FederationConfig.GetConfig();
            string findValue = federationConfig.SigningCertificate.findValue;
            MyLog.Write("SigningCertificate.findValue="+ findValue);

            X509Certificate2 x509cert = FederationConfig.GetConfig().SigningCertificate.GetCertificate();

            MyLog.Write("Was here");
            if (x509cert==null)
            {
                Trace.TraceData(TraceEventType.Verbose, "SigningCertificate not found");
                MyLog.Write("SigningCertificate not found");
            }

            RSA rsaPrivate;
            try
            {
                MyLog.Write("Before call to GetRSAPublicKey");
                RSA rsaPublic = x509cert.GetRSAPublicKey();
                MyLog.Write("Before call to GetRSAPrivateKey");
                rsaPrivate = x509cert.GetRSAPrivateKey();
            }
            catch(Exception)
            {
                MyLog.Write("Call to GetRSAPrivateKey throws exception");

                throw;
            }
            
            MyLog.Write("After call to GetRSAPrivateKey");

            if (rsaPrivate == null)
            {
                Trace.TraceData(TraceEventType.Verbose, "GetRSAPrivateKey returns null");
                MyLog.Write("GetRSAPrivateKey returns null");
            }

            MyLog.Write("A");
            KeyInfoX509Data keyClause = new KeyInfoX509Data(x509cert, X509IncludeOption.EndCertOnly);
            MyLog.Write("B");
            keyinfo.AddClause(keyClause);
            MyLog.Write("C");

            Saml20MetadataDocument doc = new Saml20MetadataDocument(configuration, keyinfo, sign);
            MyLog.Write("D");

            context.Response.Write(doc.ToXml( context.Response.ContentEncoding ));
            MyLog.Write("E");
        }

    }
}

/*
[CryptographicException: Keyset does not exist
]
System.Security.Cryptography.Utils.CreateProvHandle(CspParameters parameters, Boolean randomKeyContainer) +5341727
   System.Security.Cryptography.Utils.GetKeyPairHelper(CspAlgorithmType keyType, CspParameters parameters, Boolean randomKeyContainer, Int32 dwKeySize, SafeProvHandle& safeProvHandle, SafeKeyHandle& safeKeyHandle) +96
   System.Security.Cryptography.RSACryptoServiceProvider.GetKeyPair() +139
   System.Security.Cryptography.RSACryptoServiceProvider..ctor(Int32 dwKeySize, CspParameters parameters, Boolean useDefaultKeySize) +208
   System.Security.Cryptography.X509Certificates.X509Certificate2.get_PrivateKey() +236
   System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(X509Certificate2 certificate) +276
   dk.nita.saml20.Bindings.SignatureProviders.SignatureProvider.Sign(XmlDocument doc, String id, X509Certificate2 cert) in D:\bitbucketroot\polcam.web\libs\OIOSAML.Net\src\dk.nita.saml20\dk.nita.saml20\Bindings\SignatureProviders\SignatureProvider.cs:56
   dk.nita.saml20.Bindings.SignatureProviders.SignatureProvider.SignMetaData(XmlDocument doc, String id, X509Certificate2 cert) in D:\bitbucketroot\polcam.web\libs\OIOSAML.Net\src\dk.nita.saml20\dk.nita.saml20\Bindings\SignatureProviders\SignatureProvider.cs:48
   dk.nita.saml20.Saml20MetadataDocument.ToXml(Encoding enc) in D:\bitbucketroot\polcam.web\libs\OIOSAML.Net\src\dk.nita.saml20\dk.nita.saml20\Saml20MetadataDocument.cs:541
   dk.nita.saml20.protocol.Saml20MetadataHandler.CreateMetadataDocument(HttpContext context, Boolean sign) in 
D:\bitbucketroot\polcam.web\libs\OIOSAML.Net\src\dk.nita.saml20\dk.nita.saml20\Protocol\Saml20MetadataHandler.cs:83

   dk.nita.saml20.protocol.Saml20MetadataHandler.ProcessRequest(HttpContext context) in 
D:\bitbucketroot\polcam.web\libs\OIOSAML.Net\src\dk.nita.saml20\dk.nita.saml20\Protocol\Saml20MetadataHandler.cs:55

   System.Web.CallHandlerExecutionStep.System.Web.HttpApplication.IExecutionStep.Execute() +542
   System.Web.HttpApplication.ExecuteStepImpl(IExecutionStep step) +75
   System.Web.HttpApplication.ExecuteStep(IExecutionStep step, Boolean& completedSynchronously) +93
*/