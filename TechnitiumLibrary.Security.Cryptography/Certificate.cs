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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Security.Cryptography
{
    public enum CertificateType : byte
    {
        Normal = 0,
        RootCA = 1,
        CA = 2
    }

    public enum CertificateCapability : byte
    {
        None = 0,
        SignCACertificate = 1,
        SignNormalCertificate = 2,
        SignFile = 3,
        KeyExchange = 4
    }

    public sealed class Certificate : WriteStream
    {
        #region variables

        byte _version;
        CertificateType _type;

        string _serialNumber;
        CertificateProfile _issuedTo;
        CertificateCapability _capability;

        UInt64 _issuedOnUTC;
        UInt64 _expiresOnUTC;

        AsymmetricEncryptionAlgorithm _publicKeyEncryptionAlgorithm;
        string _publicKeyXML;

        Uri _revocationUri;

        Signature _issuerSignature;

        byte[] _LastHash;
        string _LastHashAlgo;

        #endregion

        #region constructor

        public Certificate(CertificateType type, string serialNumber, CertificateProfile issuedTo, CertificateCapability capability, DateTime issuedOnUTC, DateTime expiresOnUTC, AsymmetricEncryptionAlgorithm publicKeyEncryptionAlgorithm, string publicKeyXML)
        {
            if (issuedOnUTC > expiresOnUTC)
                throw new CryptoException("Invalid issue or expiry date. Issue date is greater than expiry date.");

            _version = 1;
            _type = type;

            _serialNumber = serialNumber;
            _issuedTo = issuedTo;
            _capability = capability;

            _issuedOnUTC = Convert.ToUInt64((issuedOnUTC - new System.DateTime(1970, 1, 1)).TotalSeconds);
            _expiresOnUTC = Convert.ToUInt64((expiresOnUTC - new System.DateTime(1970, 1, 1)).TotalSeconds);

            _publicKeyEncryptionAlgorithm = publicKeyEncryptionAlgorithm;
            _publicKeyXML = publicKeyXML;
        }

        public Certificate(Stream s)
        {
            ReadFrom(new BinaryReader(s));
        }

        public Certificate(BinaryReader bR)
        {
            ReadFrom(bR);
        }

        #endregion

        #region private

        private void ReadFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CE")
                throw new InvalidCertificateException("Invalid certificate format.");

            _version = bR.ReadByte();
            switch (_version)
            {
                case 1:
                    _type = (CertificateType)bR.ReadByte();

                    _serialNumber = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadByte()));
                    _issuedTo = new CertificateProfile(bR);
                    _capability = (CertificateCapability)bR.ReadByte();

                    _issuedOnUTC = bR.ReadUInt64();
                    _expiresOnUTC = bR.ReadUInt64();

                    _publicKeyEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm)bR.ReadByte();
                    _publicKeyXML = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadUInt16()));

                    byte rUriLen = bR.ReadByte();
                    if (rUriLen > 0)
                        _revocationUri = new Uri(Encoding.UTF8.GetString(bR.ReadBytes(rUriLen)));

                    if (bR.ReadByte() == 1)
                        _issuerSignature = new Signature(bR);

                    break;

                default:
                    throw new InvalidCertificateException("Certificate format version not supported.");
            }
        }

        private void WriteCertificateTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);
            WriteCertificateTo(bW);
            bW.Flush();
        }

        private void WriteCertificateTo(BinaryWriter bW)
        {
            bW.Write(Encoding.ASCII.GetBytes("CE"));

            bW.Write(_version);
            bW.Write((byte)_type);

            bW.Write(Convert.ToByte(_serialNumber.Length));
            bW.Write(Encoding.ASCII.GetBytes(_serialNumber));
            _issuedTo.WriteTo(bW);
            bW.Write((byte)_capability);

            bW.Write(_issuedOnUTC);
            bW.Write(_expiresOnUTC);

            bW.Write((byte)_publicKeyEncryptionAlgorithm);

            bW.Write(Convert.ToUInt16(_publicKeyXML.Length));
            bW.Write(Encoding.ASCII.GetBytes(_publicKeyXML));

            if (_revocationUri == null)
                bW.Write((byte)0);
            else
            {
                byte[] buffer = Encoding.UTF8.GetBytes(_revocationUri.AbsoluteUri);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }
        }

        #endregion

        #region public

        public void Sign(string hashAlgo, CertificateStore signingContainer, Uri revocationUri)
        {
            Sign(hashAlgo, signingContainer.Certificate, signingContainer.PrivateKey, revocationUri);
        }

        public void Sign(string hashAlgo, Certificate signingCert, AsymmetricCryptoKey privateKey, Uri revocationUri)
        {
            switch (_type)
            {
                case CertificateType.RootCA:
                    throw new CryptoException("Cannot sign a root certificate with any other certificate. Root certificate must be self signed.");

                case CertificateType.CA:
                    switch (signingCert._type)
                    {
                        case CertificateType.CA:
                        case CertificateType.RootCA:
                            if (signingCert._capability != CertificateCapability.SignCACertificate)
                                throw new CryptoException("Signing certificate must have certificate authority (CA) signing capability.");
                            break;

                        default:
                            throw new CryptoException("Signing certificate must be root certificate or a certificate authority (CA).");
                    }
                    break;

                default:
                    if (signingCert._capability != CertificateCapability.SignNormalCertificate)
                        throw new CryptoException("Signing certificate must have normal certificate signing capability.");
                    break;
            }

            _revocationUri = revocationUri;
            _issuerSignature = new Signature(GetHash(hashAlgo), hashAlgo, signingCert, privateKey);
        }

        public void SelfSign(string hashAlgo, AsymmetricCryptoKey privateKey, Uri revocationUri)
        {
            _revocationUri = revocationUri;
            _issuerSignature = new Signature(GetHash(hashAlgo), hashAlgo, null, privateKey);
        }

        public void Verify(Certificate[] trustedRootCAs)
        {
            Certificate IssuerCert = _issuerSignature.SigningCertificate;

            #region verify signature

            switch (_type)
            {
                case CertificateType.RootCA:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), this))
                        throw new InvalidCertificateException("Root CA certificate issued to '" + _issuedTo.Name + "' by self has invalid signature.");
                    break;

                case CertificateType.CA:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), trustedRootCAs))
                        throw new InvalidCertificateException("CA certificate issued to '" + _issuedTo.Name + "' by issuer '" + IssuerCert._issuedTo.Name + "' has invalid signature.");
                    break;

                default:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), trustedRootCAs))
                        throw new InvalidCertificateException("Certificate issued to '" + _issuedTo.Name + "' by issuer '" + IssuerCert._issuedTo.Name + "' has invalid signature.");
                    break;
            }

            #endregion

            #region check capability

            switch (_type)
            {
                case CertificateType.RootCA:
                    //self
                    if (_capability != CertificateCapability.SignCACertificate)
                        throw new InvalidCertificateException("Root CA certificate can only be used to sign a CA certificate.");

                    // root ca doesnt have issuer
                    break;

                case CertificateType.CA:
                    //self
                    if ((_capability != CertificateCapability.SignCACertificate) && (_capability != CertificateCapability.SignNormalCertificate))
                        throw new InvalidCertificateException("CA certificates can only be used to sign a CA or normal certificate.");

                    //ca issuer must have ca signing capability
                    if (IssuerCert._capability != CertificateCapability.SignCACertificate)
                        throw new InvalidCertificateException("CA certificate issued to '" + _issuedTo.Name + "' by issuer '" + IssuerCert._issuedTo.Name + "' doesn't have capability to sign CA certificate.");
                    break;

                default:
                    //self
                    if ((_capability == CertificateCapability.SignCACertificate) || (_capability == CertificateCapability.SignNormalCertificate))
                        throw new InvalidCertificateException("Normal certificates cannot sign other certificates.");

                    //issuer
                    if (IssuerCert._capability != CertificateCapability.SignNormalCertificate)
                        throw new InvalidCertificateException("Certificate issued to '" + _issuedTo.Name + "' by issuer '" + IssuerCert._issuedTo.Name + "' doesn't have capability to sign certificate.");
                    break;
            }

            #endregion

            #region check if root is trusted and issued date against signer date range

            switch (_type)
            {
                case CertificateType.RootCA:
                    bool trustedRootCA = false;

                    foreach (Certificate rootCA in trustedRootCAs)
                    {
                        if (this.Equals(rootCA))
                        {
                            trustedRootCA = true;
                            break;
                        }
                    }

                    if (!trustedRootCA)
                        throw new InvalidCertificateException("Root certificate issued by '" + _issuedTo.Name + "' is not trusted.");

                    break;

                default:
                    if ((IssuerCert._issuedOnUTC > _issuedOnUTC) || (_issuedOnUTC > IssuerCert._expiresOnUTC))
                        throw new InvalidCertificateException("Issuer '" + IssuerCert._issuedTo.Name + "' certificate was expired during signing certificate for '" + _issuedTo.Name + "'.");
                    break;
            }

            #endregion

            #region check if normal cert is expired

            if ((_type == CertificateType.Normal) && HasExpired())
                throw new InvalidCertificateException("Certificate issued to '" + _issuedTo.Name + "' has expired.");

            #endregion
        }

        public void VerifyRevocationList(SocksClient proxy = null)
        {
            if (_revocationUri != null)
            {
                bool revoked = false;
                RevocationCertificate revokeCert = null;

                try
                {
                    revoked = RevocationCertificate.IsRevoked(this, out revokeCert, proxy);

                    if (_issuerSignature.SigningCertificate != null)
                        _issuerSignature.SigningCertificate.VerifyRevocationList(proxy);
                }
                catch (InvalidCertificateException)
                {
                    throw;
                }
                catch
                { }

                if (revoked)
                    throw new InvalidCertificateException("Certificate serial number '" + _serialNumber + "' issued to '" + _issuedTo.Name + "' has been revoked on " + revokeCert.RevokedOnUTC + " UTC by the certificate authority and hence is invalid.");
            }
        }

        public bool HasExpired()
        {
            UInt64 currDate = Convert.ToUInt64((DateTime.UtcNow - new System.DateTime(1970, 1, 1)).TotalSeconds);
            return ((currDate < _issuedOnUTC) || (currDate > _expiresOnUTC));
        }

        public bool IsSigned()
        {
            return (_issuerSignature != null);
        }

        public override bool Equals(object obj)
        {
            if (base.Equals(obj))
                return true;

            Certificate Cert = obj as Certificate;

            if (Cert == null)
                return false;

            if (_version != Cert._version)
                return false;

            if (_type != Cert._type)
                return false;

            if (_serialNumber != Cert._serialNumber)
                return false;

            if (!_issuedTo.Equals(Cert._issuedTo))
                return false;

            if (_capability != Cert._capability)
                return false;

            if (_issuedOnUTC != Cert._issuedOnUTC)
                return false;

            if (_expiresOnUTC != Cert._expiresOnUTC)
                return false;

            if (_publicKeyEncryptionAlgorithm != Cert._publicKeyEncryptionAlgorithm)
                return false;

            if (_publicKeyXML != Cert._publicKeyXML)
                return false;

            if (_issuerSignature == Cert._issuerSignature)
                return true;

            return _issuerSignature.Equals(Cert._issuerSignature);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public byte[] GetHash(string hashAlgorithm)
        {
            if (hashAlgorithm == _LastHashAlgo)
                return _LastHash;

            using (MemoryStream mS = new MemoryStream())
            {
                WriteCertificateTo(mS);
                mS.Position = 0;

                _LastHashAlgo = hashAlgorithm;
                _LastHash = HashAlgorithm.Create(hashAlgorithm).ComputeHash(mS);

                return _LastHash;
            }
        }

        public override void WriteTo(BinaryWriter bW)
        {
            WriteCertificateTo(bW);

            if (_issuerSignature == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write((byte)1);
                _issuerSignature.WriteTo(bW);
            }
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public CertificateType Type
        { get { return _type; } }

        public string SerialNumber
        { get { return _serialNumber; } }

        public CertificateProfile IssuedTo
        { get { return _issuedTo; } }

        public CertificateCapability Capability
        { get { return _capability; } }

        public DateTime IssuedOnUTC
        { get { return new System.DateTime(1970, 1, 1).AddSeconds(_issuedOnUTC); } }

        public DateTime ExpiresOnUTC
        { get { return new System.DateTime(1970, 1, 1).AddSeconds(_expiresOnUTC); } }

        public AsymmetricEncryptionAlgorithm PublicKeyEncryptionAlgorithm
        { get { return _publicKeyEncryptionAlgorithm; } }

        public string PublicKeyXML
        { get { return _publicKeyXML; } }

        public Signature IssuerSignature
        { get { return _issuerSignature; } }

        public Uri RevocationURL
        { get { return _revocationUri; } }

        #endregion
    }
}