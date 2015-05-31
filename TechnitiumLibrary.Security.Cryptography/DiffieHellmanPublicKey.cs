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
using System.Numerics;
using System.Xml;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class DiffieHellmanPublicKey
    {
        #region variables

        int _keySize;
        BigInteger _p;
        BigInteger _g;
        BigInteger _x;

        #endregion

        #region constructor

        public DiffieHellmanPublicKey(int keySize, BigInteger p, BigInteger g, BigInteger x)
        {
            _keySize = keySize;
            _p = p;
            _g = g;
            _x = x;
        }

        public DiffieHellmanPublicKey(string publicKeyXML)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(publicKeyXML);

            XmlNode DHPublicKey = xmlDoc.SelectSingleNode("DHPublicKey");

            _keySize = int.Parse(DHPublicKey.Attributes["keySize"].Value);

            switch (DHPublicKey.Attributes["encoding"].Value)
            {
                case "base64":
                    _p = new BigInteger(Convert.FromBase64String(DHPublicKey.SelectSingleNode("P").InnerText));
                    _g = new BigInteger(Convert.FromBase64String(DHPublicKey.SelectSingleNode("G").InnerText));
                    _x = new BigInteger(Convert.FromBase64String(DHPublicKey.SelectSingleNode("X").InnerText));
                    break;

                default:
                    throw new CryptoException("DiffieHellman public key xml encoding not supported.");
            }
        }

        #endregion

        #region public

        public string PublicKeyXML()
        {
            return @"<?xml version=""1.0"" encoding=""UTF-8""?>
<DHPublicKey keySize=""" + _keySize + @""" encoding=""base64"">
    <P>" + Convert.ToBase64String(_p.ToByteArray()) + @"</P>
    <G>" + Convert.ToBase64String(_g.ToByteArray()) + @"</G>
    <X>" + Convert.ToBase64String(_x.ToByteArray()) + @"</X>
</DHPublicKey>
";
        }

        #endregion

        #region properties

        public int KeySize
        { get { return _keySize; } }

        public BigInteger P
        { get { return _p; } }

        public BigInteger G
        { get { return _g; } }

        public BigInteger X
        { get { return _x; } }

        #endregion
    }
}
