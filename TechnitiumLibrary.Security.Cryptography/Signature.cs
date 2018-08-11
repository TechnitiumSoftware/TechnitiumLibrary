/*
Technitium Library
Copyright (C) 2016  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;

namespace TechnitiumLibrary.Security.Cryptography
{
    public sealed class Signature
    {
        #region variables

        byte[] _signedHash;
        string _hashAlgo;
        AsymmetricEncryptionAlgorithm _signAlgo;
        Certificate _signingCert;

        #endregion

        #region constructor

        public Signature(byte[] hash, string hashAlgo, Certificate signingCert, AsymmetricCryptoKey privateKey)
        {
            _signedHash = privateKey.Sign(hash, hashAlgo);
            _hashAlgo = hashAlgo;
            _signAlgo = privateKey.Algorithm;
            _signingCert = signingCert;
        }

        public Signature(Stream data, string hashAlgo, Certificate signingCert, AsymmetricCryptoKey privateKey)
        {
            _signedHash = privateKey.Sign(data, hashAlgo);
            _hashAlgo = hashAlgo;
            _signAlgo = privateKey.Algorithm;
            _signingCert = signingCert;
        }

        public Signature(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "SN") //format
                throw new CryptoException("Invalid signature format.");

            switch (bR.ReadByte()) //version 
            {
                case 1:
                    _signedHash = bR.ReadBytes(bR.ReadUInt16());
                    _hashAlgo = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadByte()));
                    _signAlgo = (AsymmetricEncryptionAlgorithm)bR.ReadByte();

                    if (s.ReadByte() == 1)
                        _signingCert = new Certificate(s);

                    break;

                default:
                    throw new CryptoException("Signature format version not supported.");
            }
        }

        #endregion

        #region public

        public bool Verify(Stream data, Certificate[] trustedRootCAs)
        {
            return Verify(System.Security.Cryptography.HashAlgorithm.Create(_hashAlgo).ComputeHash(data), trustedRootCAs);
        }

        public bool Verify(byte[] hash, Certificate[] trustedRootCAs)
        {
            if (AsymmetricCryptoKey.Verify(hash, _signedHash, _hashAlgo, _signingCert))
            {
                _signingCert.Verify(trustedRootCAs);

                return true;
            }
            else
            {
                return false;
            }
        }

        public bool Verify(byte[] hash, Certificate signingCert)
        {
            return AsymmetricCryptoKey.Verify(hash, _signedHash, _hashAlgo, signingCert);
        }

        public void WriteTo(Stream s)
        {
            s.Write(Encoding.ASCII.GetBytes("SN"), 0, 2); //format
            s.WriteByte((byte)1);

            s.Write(BitConverter.GetBytes(Convert.ToUInt16(_signedHash.Length)), 0, 2);
            s.Write(_signedHash, 0, _signedHash.Length);

            s.WriteByte(Convert.ToByte(_hashAlgo.Length));
            s.Write(Encoding.ASCII.GetBytes(_hashAlgo), 0, _hashAlgo.Length);

            s.WriteByte((byte)_signAlgo);

            if (_signingCert == null)
            {
                s.WriteByte((byte)0);
            }
            else
            {
                s.WriteByte((byte)1);
                _signingCert.WriteTo(s);
            }
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            Signature s = obj as Signature;

            if (s == null)
                return false;

            if (s._hashAlgo != _hashAlgo)
                return false;

            if (s._signedHash.Length != _signedHash.Length)
                return false;

            for (int i = 0; i < _signedHash.Length; i++)
                if (s._signedHash[i] != _signedHash[i])
                    return false;

            if (s._signingCert == _signingCert)
                return true;

            return (s._signingCert.Equals(_signingCert));
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override string ToString()
        {
            return "<Signature>" + Convert.ToBase64String(_signedHash) + "</Signature>";
        }

        #endregion

        #region properties

        public string HashAlgorithm
        { get { return _hashAlgo; } }

        public AsymmetricEncryptionAlgorithm SignatureAlgorithm
        { get { return _signAlgo; } }

        public Certificate SigningCertificate
        { get { return _signingCert; } }

        #endregion
    }
}