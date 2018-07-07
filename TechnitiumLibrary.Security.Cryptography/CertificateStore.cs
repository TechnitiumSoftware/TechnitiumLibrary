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

        #endregion

        #region IDisposable

        bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_privateKey != null)
                    _privateKey.Dispose();
            }

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region private

        protected override void ReadPlainTextFrom(Stream s)
        {
            byte[] format = new byte[2];
            s.Read(format, 0, 2);

            if (Encoding.ASCII.GetString(format) != "CS")
                throw new InvalidCryptoContainerException("Invalid CertificateStore format.");

            switch (s.ReadByte()) //version
            {
                case 1:
                    _cert = new Certificate(s);
                    _privateKey = new AsymmetricCryptoKey(s);
                    break;

                case -1:
                    throw new EndOfStreamException();

                default:
                    throw new CryptoException("CertificateStore format version not supported.");
            }
        }

        protected override void WritePlainTextTo(Stream s)
        {
            s.Write(Encoding.ASCII.GetBytes("CS"), 0, 2); //format
            s.WriteByte((byte)1); //version

            _cert.WriteTo(s);
            _privateKey.WriteTo(s);
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
