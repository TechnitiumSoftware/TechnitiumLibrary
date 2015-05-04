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
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Security.Cryptography
{
    public abstract class CryptoContainer : WriteStream
    {
        #region variables

        SymmetricCryptoKey _containerKey;

        #endregion

        #region constructor

        public CryptoContainer()
        { }

        public CryptoContainer(SymmetricEncryptionAlgorithm cryptoAlgo, int keySize, string password)
        {
            _containerKey = new SymmetricCryptoKey(cryptoAlgo, keySize, password);
        }

        public CryptoContainer(Stream s, string password = null)
        {
            ReadFrom(new BinaryReader(s), password);
        }

        public CryptoContainer(BinaryReader bR, string password = null)
        {
            ReadFrom(bR, password);
        }

        #endregion

        #region protected abstract

        private void ReadFrom(BinaryReader bR, string password = null)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CC")
                throw new InvalidCryptoContainerException("Invalid CryptoContainer format.");

            switch (bR.ReadByte()) //version
            {
                case 0:
                    ReadPlainTextFrom(bR);
                    break;

                case 1:
                    if (password == null)
                        throw new InvalidCryptoContainerException("Password required.");

                    //CryptoAlgo
                    SymmetricEncryptionAlgorithm cryptoAlgo = (SymmetricEncryptionAlgorithm)bR.ReadByte();

                    //KeySizeBytes
                    int keySizeBytes = bR.ReadByte();

                    //IV
                    byte[] IV = bR.ReadBytes(bR.ReadByte());

                    _containerKey = new SymmetricCryptoKey(cryptoAlgo, keySizeBytes * 8, password, IV);

                    ReadPlainTextFrom(new BinaryReader(_containerKey.GetCryptoStreamReader(bR.BaseStream)));
                    break;

                default:
                    throw new InvalidCryptoContainerException("CryptoContainer format version not supported.");
            }
        }

        protected abstract void ReadPlainTextFrom(BinaryReader bR);

        protected abstract void WritePlainTextTo(BinaryWriter bW);

        #endregion

        #region public

        public sealed override void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("CC"), 0, 2); //format

            if (_containerKey == null)
            {
                bW.Write((byte)0); //version 0 = plain text
                WritePlainTextTo(bW);
            }
            else
            {
                bW.Write((byte)1); //version
                bW.Write((byte)_containerKey.Algorithm); //CryptoAlgoName
                bW.Write(Convert.ToByte(_containerKey.KeySize / 8)); //KeySizeBytes
                bW.Write(Convert.ToByte(_containerKey.IV.Length)); //IV Size
                bW.Write(_containerKey.IV, 0, _containerKey.IV.Length); //IV
                bW.Flush();

                CryptoStream c = _containerKey.GetCryptoStreamWriter(bW.BaseStream);

                BinaryWriter bW2 = new BinaryWriter(c);
                WritePlainTextTo(bW2);
                bW2.Flush();

                c.FlushFinalBlock();
            }
        }

        public void SetPassword(SymmetricEncryptionAlgorithm cryptoAlgo, int keySize, string password)
        {
            _containerKey = new SymmetricCryptoKey(cryptoAlgo, keySize, password);
        }

        public void ChangePassword(string password = null)
        {
            if (_containerKey == null)
                throw new CryptoException("Cannot change password. Use SetPassword() instead.");

            if (password == null)
                _containerKey = null;
            else
                _containerKey = new SymmetricCryptoKey(_containerKey.Algorithm, _containerKey.KeySize, password);
        }

        #endregion
    }
}
