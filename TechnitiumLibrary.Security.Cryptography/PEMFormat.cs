using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class PEMFormat
    {
        public static RSAParameters ReadRSAPrivateKey(Stream s)
        {
            using (StreamReader sR = new StreamReader(s))
            {
                if (sR.ReadLine() != "-----BEGIN RSA PRIVATE KEY-----")
                    throw new IOException("The data should begin with header: -----BEGIN RSA PRIVATE KEY-----");

                StringBuilder base64Data = new StringBuilder(2048);

                do
                {
                    string line = sR.ReadLine();

                    if (line == "-----END RSA PRIVATE KEY-----")
                        break;

                    base64Data.Append(line);
                }
                while (true);

                DEREncoding obj = DEREncoding.Decode(Convert.FromBase64String(base64Data.ToString()));

                using (Stream sV = obj.GetValueStream())
                {
                    DEREncoding objVer = DEREncoding.Decode(sV);

                    if (objVer.Value[0] != 0)
                        throw new IOException("Unknown version number for RSA private key data.");

                    DEREncoding objModulus = DEREncoding.Decode(sV);
                    DEREncoding objExponent = DEREncoding.Decode(sV);
                    DEREncoding objD = DEREncoding.Decode(sV);
                    DEREncoding objP = DEREncoding.Decode(sV);
                    DEREncoding objQ = DEREncoding.Decode(sV);
                    DEREncoding objDP = DEREncoding.Decode(sV);
                    DEREncoding objDQ = DEREncoding.Decode(sV);
                    DEREncoding objInverseQ = DEREncoding.Decode(sV);

                    RSAParameters parameters = new RSAParameters();

                    parameters.Modulus = objModulus.GetIntegerValue();
                    parameters.Exponent = objExponent.GetIntegerValue();
                    parameters.D = objD.GetIntegerValue();
                    parameters.P = objP.GetIntegerValue();
                    parameters.Q = objQ.GetIntegerValue();
                    parameters.DP = objDP.GetIntegerValue();
                    parameters.DQ = objDQ.GetIntegerValue();
                    parameters.InverseQ = objInverseQ.GetIntegerValue();

                    return parameters;
                }
            }
        }
    }
}
