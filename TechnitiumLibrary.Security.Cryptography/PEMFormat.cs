/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

                return DEREncoding.DecodeRSAPrivateKey(Convert.FromBase64String(base64Data.ToString()));
            }
        }

        public static void WriteRSAPrivateKey(RSAParameters parameters, Stream s)
        {
            byte[] header = Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----\n");
            byte[] footer = Encoding.UTF8.GetBytes("-----END RSA PRIVATE KEY-----\n");
            byte[] base64data;

            //get base64 encoded DER formatted data
            base64data = Encoding.UTF8.GetBytes(Convert.ToBase64String(DEREncoding.EncodeRSAPrivateKey(parameters)));

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

        public static RSAParameters ReadRSAPublicKey(Stream s)
        {
            using (StreamReader sR = new StreamReader(s))
            {
                if (sR.ReadLine() != "-----BEGIN RSA PUBLIC KEY-----")
                    throw new IOException("The data should begin with header: -----BEGIN RSA PUBLIC KEY-----");

                StringBuilder base64Data = new StringBuilder(2048);

                do
                {
                    string line = sR.ReadLine();

                    if (line == "-----END RSA PUBLIC KEY-----")
                        break;

                    base64Data.Append(line);
                }
                while (true);

                return DEREncoding.DecodeRSAPublicKey(Convert.FromBase64String(base64Data.ToString()));
            }
        }

        public static void WriteRSAPublicKey(RSAParameters parameters, Stream s)
        {
            byte[] header = Encoding.UTF8.GetBytes("-----BEGIN RSA PUBLIC KEY-----\n");
            byte[] footer = Encoding.UTF8.GetBytes("-----END RSA PUBLIC KEY-----\n");
            byte[] base64data;

            //get base64 encoded DER formatted data
            base64data = Encoding.UTF8.GetBytes(Convert.ToBase64String(DEREncoding.EncodeRSAPublicKey(parameters)));

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
