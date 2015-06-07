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

        DiffieHellmanGroupType _group;
        int _keySize;
        BigInteger _p;
        BigInteger _g;
        BigInteger _x;

        #endregion

        #region constructor

        public DiffieHellmanPublicKey(DiffieHellmanGroupType group, int keySize, BigInteger x)
        {
            _group = group;
            _keySize = keySize;
            _x = x;

            DiffieHellmanGroup dhg = DiffieHellmanGroup.GetGroup(group, keySize);
            VerifyPublicKey(_keySize, dhg.P, dhg.G, x);
        }

        public DiffieHellmanPublicKey(int keySize, BigInteger p, BigInteger g, BigInteger x)
        {
            _group = DiffieHellmanGroupType.None;
            _keySize = keySize;
            _p = p;
            _g = g;
            _x = x;

            VerifyPublicKey(_keySize, _p, _g, _x);
        }

        public DiffieHellmanPublicKey(string publicKeyXML)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(publicKeyXML);

            XmlNode DHPublicKey = xmlDoc.SelectSingleNode("DHPublicKey");

            _keySize = int.Parse(DHPublicKey.Attributes["keySize"].Value);

            if (DHPublicKey.Attributes["group"] == null)
                _group = DiffieHellmanGroupType.None;
            else
                _group = (DiffieHellmanGroupType)int.Parse(DHPublicKey.Attributes["group"].Value);

            switch (DHPublicKey.Attributes["encoding"].Value)
            {
                case "base64":
                    if (_group == DiffieHellmanGroupType.None)
                    {
                        _p = ReadPositiveNumber(DHPublicKey.SelectSingleNode("P").InnerText);
                        _g = ReadPositiveNumber(DHPublicKey.SelectSingleNode("G").InnerText);
                    }
                    else
                    {
                        DiffieHellmanGroup dhg = DiffieHellmanGroup.GetGroup(_group, _keySize);
                        _p = dhg.P;
                        _g = dhg.G;
                    }

                    _x = ReadPositiveNumber(DHPublicKey.SelectSingleNode("X").InnerText);
                    break;

                default:
                    throw new CryptoException("DiffieHellman public key xml encoding not supported.");
            }

            VerifyPublicKey(_keySize, _p, _g, _x);
        }

        #endregion

        #region private

        private static BigInteger ReadPositiveNumber(string base64Data)
        {
            byte[] buffer = Convert.FromBase64String(base64Data);

            if (buffer[buffer.Length - 1] == 0)
                return new BigInteger(buffer);

            byte[] buffer2 = new byte[buffer.Length + 1];
            Buffer.BlockCopy(buffer, 0, buffer2, 0, buffer.Length);
            return new BigInteger(buffer2);
        }

        private static void VerifyPublicKey(int keySize, BigInteger p, BigInteger g, BigInteger x)
        {
            if ((keySize - (p.ToByteArray().Length << 3)) > 32)
                throw new CryptoException("DiffieHellman invalid public key parameter.");

            BigInteger pm2 = p - 2;

            if ((x < 2) || (x > pm2))
                throw new CryptoException("DiffieHellman invalid public key parameter.");

            if ((g < 2) || (g > pm2))
                throw new CryptoException("DiffieHellman invalid public key parameter.");
        }

        #endregion

        #region public

        public string PublicKeyXML()
        {
            switch (_group)
            {
                case DiffieHellmanGroupType.RFC3526:
                    return @"<?xml version=""1.0"" encoding=""UTF-8""?>
<DHPublicKey keySize=""" + _keySize + @""" group=""" + (int)_group + @""" encoding=""base64"">
    <X>" + Convert.ToBase64String(_x.ToByteArray()) + @"</X>
</DHPublicKey>";

                default:
                    return @"<?xml version=""1.0"" encoding=""UTF-8""?>
<DHPublicKey keySize=""" + _keySize + @""" encoding=""base64"">
    <P>" + Convert.ToBase64String(_p.ToByteArray()) + @"</P>
    <G>" + Convert.ToBase64String(_g.ToByteArray()) + @"</G>
    <X>" + Convert.ToBase64String(_x.ToByteArray()) + @"</X>
</DHPublicKey>";
            }
        }

        #endregion

        #region properties

        public DiffieHellmanGroupType Group
        { get { return _group; } }

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
