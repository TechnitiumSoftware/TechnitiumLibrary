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
    public enum AsymmetricEncryptionAlgorithm : byte
    {
        Unknown = 0,
        RSA = 1,
        DSA = 2,
    }

    public sealed class AsymmetricCryptoKey : WriteStream, IDisposable
    {
        #region variables

        AsymmetricAlgorithm _asymAlgo;
        AsymmetricEncryptionAlgorithm _cryptoAlgo;

        #endregion

        #region constructor

        public AsymmetricCryptoKey(AsymmetricEncryptionAlgorithm cryptoAlgo, int keySize)
        {
            switch (cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
                    rsa.PersistKeyInCsp = false;
                    _asymAlgo = rsa;
                    break;

                case AsymmetricEncryptionAlgorithm.DSA:
                    DSACryptoServiceProvider dsa = new DSACryptoServiceProvider(keySize);
                    dsa.PersistKeyInCsp = false;
                    _asymAlgo = dsa;
                    break;

                //case AsymmetricEncryptionAlgorithm.ECDiffieHellman:

                //    break;

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }

            _cryptoAlgo = cryptoAlgo;
        }

        public AsymmetricCryptoKey(Stream s)
        {
            ReadFrom(new BinaryReader(s));
        }

        public AsymmetricCryptoKey(BinaryReader bR)
        {
            ReadFrom(bR);
        }

        #endregion

        #region IDisposable

        bool _disposed = false;

        ~AsymmetricCryptoKey()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
        }

        private void Dispose(bool Disposing)
        {
            if (!_disposed)
            {
                _asymAlgo.Clear();
                _disposed = true;
            }
        }

        #endregion

        #region private

        private void ReadFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AK")
                throw new CryptoException("Invalid AsymmetricCryptoKey format.");

            switch (bR.ReadByte()) //version
            {
                case 1:
                    AsymmetricEncryptionAlgorithm cryptoAlgo = (AsymmetricEncryptionAlgorithm)bR.ReadByte();
                    string privateKey = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadUInt16()));

                    switch (cryptoAlgo)
                    {
                        case AsymmetricEncryptionAlgorithm.RSA:
                            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                            rsa.PersistKeyInCsp = false;
                            rsa.FromXmlString(privateKey);
                            _asymAlgo = rsa;
                            break;

                        case AsymmetricEncryptionAlgorithm.DSA:
                            DSACryptoServiceProvider dsa = new DSACryptoServiceProvider();
                            dsa.PersistKeyInCsp = false;
                            dsa.FromXmlString(privateKey);
                            _asymAlgo = dsa;
                            break;

                        default:
                            throw new NotImplementedException("Feature not implemented for specified algorithm.");
                    }

                    _cryptoAlgo = cryptoAlgo;
                    break;

                default:
                    throw new CryptoException("AsymmetricCryptoKey format version not supported.");
            }
        }

        #endregion

        #region static

        public static byte[] Encrypt(byte[] data, AsymmetricEncryptionAlgorithm cryptoAlgo, string publicKey)
        {
            switch (cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.PersistKeyInCsp = false;
                    rsa.FromXmlString(publicKey);
                    return rsa.Encrypt(data, false);

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public static byte[] Decrypt(byte[] data, AsymmetricEncryptionAlgorithm cryptoAlgo, string privateKey)
        {
            switch (cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.PersistKeyInCsp = false;
                    rsa.FromXmlString(privateKey);
                    return rsa.Decrypt(data, false);

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public static bool Verify(Stream data, byte[] signedHash, string hashAlgo, Certificate signingCert)
        {
            return Verify(HashAlgorithm.Create(hashAlgo).ComputeHash(data), signedHash, hashAlgo, signingCert.PublicKeyEncryptionAlgorithm, signingCert.PublicKeyXML);
        }

        public static bool Verify(byte[] hash, byte[] signedHash, string hashAlgo, Certificate signingCert)
        {
            return Verify(hash, signedHash, hashAlgo, signingCert.PublicKeyEncryptionAlgorithm, signingCert.PublicKeyXML);
        }

        public static bool Verify(byte[] hash, byte[] signedHash, string hashAlgo, AsymmetricEncryptionAlgorithm cryptoAlgo, string publicKey)
        {
            switch (cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                    {
                        RSA.FromXmlString(publicKey);

                        return RSA.VerifyHash(hash, CryptoConfig.MapNameToOID(hashAlgo), signedHash);
                    }

                case AsymmetricEncryptionAlgorithm.DSA:
                    using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
                    {
                        DSA.FromXmlString(publicKey);

                        DSASignatureDeformatter DSADeformatter = new DSASignatureDeformatter(DSA);
                        DSADeformatter.SetHashAlgorithm(hashAlgo);

                        return DSADeformatter.VerifySignature(hash, signedHash);
                    }

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public static byte[] Sign(Stream data, string hashAlgo, AsymmetricEncryptionAlgorithm cryptoAlgo, string privateKey)
        {
            return Sign(HashAlgorithm.Create(hashAlgo).ComputeHash(data), hashAlgo, cryptoAlgo, privateKey);
        }

        public static byte[] Sign(byte[] hash, string hashAlgo, AsymmetricEncryptionAlgorithm cryptoAlgo, string privateKey)
        {
            switch (cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                    {
                        RSA.FromXmlString(privateKey);

                        return RSA.SignHash(hash, CryptoConfig.MapNameToOID(hashAlgo));
                    }

                case AsymmetricEncryptionAlgorithm.DSA:
                    using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
                    {
                        DSA.FromXmlString(privateKey);

                        DSASignatureFormatter DSAFormatter = new DSASignatureFormatter(DSA);
                        DSAFormatter.SetHashAlgorithm(hashAlgo);

                        return DSAFormatter.CreateSignature(hash);
                    }

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        #endregion

        #region public

        public override void WriteTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("AK"));
            bW.Write((byte)1); //version
            bW.Write((byte)_cryptoAlgo);

            string Key = _asymAlgo.ToXmlString(true);
            bW.Write(Convert.ToUInt16(Key.Length));
            bW.Write(Encoding.ASCII.GetBytes(Key));
        }

        public string GetPublicKey()
        {
            return _asymAlgo.ToXmlString(false);
        }

        public AsymmetricEncryptionAlgorithm Algorithm
        { get { return _cryptoAlgo; } }

        #endregion

        #region Asymmetric Crypto Key Methods

        public byte[] Encrypt(byte[] data)
        {
            switch (_cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider rsa = _asymAlgo as RSACryptoServiceProvider;
                    return rsa.Encrypt(data, false);

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            switch (_cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider rsa = _asymAlgo as RSACryptoServiceProvider;
                    return rsa.Decrypt(data, false);

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public bool Verify(Stream data, byte[] signedHash, string hashAlgo)
        {
            return Verify(HashAlgorithm.Create(hashAlgo).ComputeHash(data), signedHash, hashAlgo);
        }

        public bool Verify(byte[] hash, byte[] signedHash, string hashAlgo)
        {
            switch (_cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)_asymAlgo;
                    return RSA.VerifyHash(hash, CryptoConfig.MapNameToOID(hashAlgo), signedHash);

                case AsymmetricEncryptionAlgorithm.DSA:
                    DSASignatureDeformatter DSADeformatter = new DSASignatureDeformatter(_asymAlgo);
                    DSADeformatter.SetHashAlgorithm(hashAlgo);
                    return DSADeformatter.VerifySignature(hash, signedHash);

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        public byte[] Sign(Stream data, string hashAlgo)
        {
            return Sign(HashAlgorithm.Create(hashAlgo).ComputeHash(data), hashAlgo);
        }

        public byte[] Sign(byte[] hash, string hashAlgo)
        {
            switch (_cryptoAlgo)
            {
                case AsymmetricEncryptionAlgorithm.DSA:
                    DSASignatureFormatter DSAFormatter = new DSASignatureFormatter(_asymAlgo);
                    DSAFormatter.SetHashAlgorithm(hashAlgo);
                    return DSAFormatter.CreateSignature(hash);

                case AsymmetricEncryptionAlgorithm.RSA:
                    RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)_asymAlgo;
                    return RSA.SignHash(hash, CryptoConfig.MapNameToOID(hashAlgo));

                default:
                    throw new NotImplementedException("Feature not implemented for specified algorithm.");
            }
        }

        #endregion
    }
}