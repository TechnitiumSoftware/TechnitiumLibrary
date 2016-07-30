/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

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

        public static void WriteRSAPrivateKey(RSAParameters parameters, Stream s)
        {
            byte[] header = Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----\n");
            byte[] footer = Encoding.UTF8.GetBytes("-----END RSA PRIVATE KEY-----\n");
            byte[] base64data;

            //encode using DER Encoding
            using (MemoryStream derStream = new MemoryStream())
            {
                using (MemoryStream seqStream = new MemoryStream())
                {
                    DEREncoding.Encode(DEREncodingASN1Type.INTEGER, new byte[] { 0 }, seqStream); //version

                    DEREncoding.EncodeIntegerValue(parameters.Modulus, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.Exponent, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.D, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.P, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.Q, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.DP, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.DQ, seqStream);
                    DEREncoding.EncodeIntegerValue(parameters.InverseQ, seqStream);

                    //write sequence
                    DEREncoding.Encode(DEREncodingASN1Type.SEQUENCE, seqStream.ToArray(), derStream);
                }

                //get base64 formatted DER data
                base64data = Encoding.UTF8.GetBytes(Convert.ToBase64String(derStream.ToArray()));
            }

            //write PEM format
            s.Write(header, 0, header.Length);

            int offset = 0;
            int bytesRemaining = base64data.Length;
            int count = 65;

            while (bytesRemaining > 0)
            {
                if (bytesRemaining < count)
                    count = bytesRemaining;

                s.Write(base64data, offset, count);
                s.WriteByte(0x0A);

                offset += count;
                bytesRemaining -= count;
            }

            s.Write(footer, 0, footer.Length);
        }
    }
}
