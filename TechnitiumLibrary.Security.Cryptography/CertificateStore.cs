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

using System.IO;
using System.Text;

namespace TechnitiumLibrary.Security.Cryptography
{
    public sealed class CertificateStore : CryptoContainer
    {
        #region variables

        Certificate _cert;
        AsymmetricCryptoKey _privateKey;

        #endregion

        #region constructor

        public CertificateStore(Certificate cert, AsymmetricCryptoKey privateKey)
        {
            _cert = cert;
            _privateKey = privateKey;
        }

        public CertificateStore(Certificate cert, AsymmetricCryptoKey privateKey, string password)
            : base(SymmetricEncryptionAlgorithm.Rijndael, 256, password)
        {
            _cert = cert;
            _privateKey = privateKey;
        }

        public CertificateStore(string file, string password)
            : base(file, password)
        { }

        public CertificateStore(Stream s, string password)
            : base(s, password)
        { }

        public CertificateStore(Stream s)
            : base(s, null)
        { }

        public CertificateStore(BinaryReader bR, string password)
            : base(bR, password)
        { }

        public CertificateStore(BinaryReader bR)
            : base(bR, null)
        { }

        #endregion

        #region IDisposable

        ~CertificateStore()
        {
            Dispose(false);
        }

        bool disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (_privateKey != null)
                    _privateKey.Dispose();

                disposed = true;
            }

            base.Dispose(disposing);
        }

        #endregion

        #region private

        protected override void ReadPlainTextFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CS")
                throw new InvalidCryptoContainerException("Invalid CertificateStore format.");

            switch (bR.ReadByte()) //version
            {
                case 1:
                    _cert = new Certificate(bR);
                    _privateKey = new AsymmetricCryptoKey(bR);
                    break;

                default:
                    throw new CryptoException("CertificateStore format version not supported.");
            }
        }

        protected override void WritePlainTextTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("CS")); //format
            bW.Write((byte)1); //version

            _cert.WriteTo(bW);
            _privateKey.WriteTo(bW);

            bW.Flush();
        }

        #endregion

        #region properties

        public Certificate Certificate
        { get { return _cert; } }

        public AsymmetricCryptoKey PrivateKey
        { get { return _privateKey; } }

        #endregion
    }
}
