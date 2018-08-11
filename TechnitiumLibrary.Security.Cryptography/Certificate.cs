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
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Security.Cryptography
{
    public enum CertificateType : byte
    {
        User = 0,
        RootCA = 1,
        CA = 2
    }

    public enum CertificateCapability : byte
    {
        None = 0,
        SignCACertificate = 1,
        SignAnyUserCertificate = 2,
        SignDocument = 3,
        UserAuthentication = 4,
        SignDomainUserCertificate = 5
    }

    public sealed class Certificate
    {
        #region variables

        static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        byte _version;
        CertificateType _type;

        string _serialNumber;
        CertificateProfile _issuedTo;
        CertificateCapability _capability;

        ulong _issuedOnUTC;
        ulong _expiresOnUTC;

        AsymmetricEncryptionAlgorithm _publicKeyEncryptionAlgorithm;
        string _publicKeyXML;

        Uri _revocationUri;

        Signature _issuerSignature;

        byte[] _lastHash;
        string _lastHashAlgo;

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

            _issuedOnUTC = Convert.ToUInt64((issuedOnUTC - _epoch).TotalSeconds);
            _expiresOnUTC = Convert.ToUInt64((expiresOnUTC - _epoch).TotalSeconds);

            _publicKeyEncryptionAlgorithm = publicKeyEncryptionAlgorithm;
            _publicKeyXML = publicKeyXML;
        }

        public Certificate(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CE")
                throw new InvalidCertificateException("Invalid certificate format.");

            _version = bR.ReadByte();
            switch (_version)
            {
                case 1:
                    _type = (CertificateType)bR.ReadByte();

                    _serialNumber = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadByte()));
                    _issuedTo = new CertificateProfile(s);
                    _capability = (CertificateCapability)bR.ReadByte();

                    _issuedOnUTC = bR.ReadUInt64();
                    _expiresOnUTC = bR.ReadUInt64();

                    _publicKeyEncryptionAlgorithm = (AsymmetricEncryptionAlgorithm)bR.ReadByte();
                    _publicKeyXML = Encoding.ASCII.GetString(bR.ReadBytes(bR.ReadUInt16()));

                    byte rUriLen = bR.ReadByte();
                    if (rUriLen > 0)
                        _revocationUri = new Uri(Encoding.UTF8.GetString(bR.ReadBytes(rUriLen)));

                    if (s.ReadByte() == 1)
                        _issuerSignature = new Signature(s);

                    break;

                default:
                    throw new InvalidCertificateException("Certificate format version not supported.");
            }
        }

        #endregion

        #region private

        private void WriteCertificateTo(Stream s)
        {
            s.Write(Encoding.ASCII.GetBytes("CE"), 0, 2);
            s.WriteByte(_version);

            s.WriteByte((byte)_type);

            s.WriteByte(Convert.ToByte(_serialNumber.Length));
            s.Write(Encoding.ASCII.GetBytes(_serialNumber), 0, _serialNumber.Length);

            _issuedTo.WriteTo(s);

            s.WriteByte((byte)_capability);

            s.Write(BitConverter.GetBytes(_issuedOnUTC), 0, 8);
            s.Write(BitConverter.GetBytes(_expiresOnUTC), 0, 8);

            s.WriteByte((byte)_publicKeyEncryptionAlgorithm);

            s.Write(BitConverter.GetBytes(Convert.ToUInt16(_publicKeyXML.Length)), 0, 2);
            s.Write(Encoding.ASCII.GetBytes(_publicKeyXML), 0, _publicKeyXML.Length);

            if (_revocationUri == null)
                s.WriteByte((byte)0);
            else
            {
                byte[] buffer = Encoding.UTF8.GetBytes(_revocationUri.AbsoluteUri);
                s.WriteByte(Convert.ToByte(buffer.Length));
                s.Write(buffer, 0, buffer.Length);
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
                    switch (signingCert._capability)
                    {
                        case CertificateCapability.SignAnyUserCertificate:
                            break;

                        case CertificateCapability.SignDomainUserCertificate:
                            //check if issuer email domain matches with user email domain

                            if (!_issuedTo.FieldExists(CertificateProfileFlags.EmailAddress) || !signingCert.IssuedTo.EmailAddress.Host.Equals(_issuedTo.EmailAddress.Host, StringComparison.CurrentCultureIgnoreCase))
                                throw new CryptoException("Signing certificate domain must match with user certificate email address domain.");

                            break;

                        default:
                            throw new CryptoException("Signing certificate must have user certificate signing capability.");
                    }
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
            Certificate issuerCert = _issuerSignature.SigningCertificate;

            #region verify signature

            switch (_type)
            {
                case CertificateType.RootCA:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), this))
                        throw new InvalidCertificateException("Root CA certificate issued to '" + _issuedTo.Name + "' by self has invalid signature.");
                    break;

                case CertificateType.CA:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), trustedRootCAs))
                        throw new InvalidCertificateException("CA certificate issued to '" + _issuedTo.Name + "' by issuer '" + issuerCert._issuedTo.Name + "' has invalid signature.");
                    break;

                default:
                    if (!_issuerSignature.Verify(GetHash(_issuerSignature.HashAlgorithm), trustedRootCAs))
                        throw new InvalidCertificateException("Certificate issued to '" + _issuedTo.Name + "' by issuer '" + issuerCert._issuedTo.Name + "' has invalid signature.");
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

                    //root ca doesnt have issuer
                    break;

                case CertificateType.CA:
                    //self
                    switch (_capability)
                    {
                        case CertificateCapability.SignCACertificate:
                        case CertificateCapability.SignAnyUserCertificate:
                        case CertificateCapability.SignDomainUserCertificate:
                            break;

                        default:
                            throw new InvalidCertificateException("CA certificates can only be used to sign a CA or user certificate.");
                    }

                    //ca issuer must have ca signing capability
                    if (issuerCert._capability != CertificateCapability.SignCACertificate)
                        throw new InvalidCertificateException("CA certificate issuer '" + issuerCert._issuedTo.Name + "' doesn't have capability to sign CA certificate.");
                    break;

                default:
                    //self
                    switch (_capability)
                    {
                        case CertificateCapability.SignCACertificate:
                        case CertificateCapability.SignAnyUserCertificate:
                        case CertificateCapability.SignDomainUserCertificate:
                            throw new InvalidCertificateException("User certificate cannot sign other certificates.");
                    }

                    //issuer
                    switch (issuerCert._capability)
                    {
                        case CertificateCapability.SignAnyUserCertificate:
                            break;

                        case CertificateCapability.SignDomainUserCertificate:
                            //check if issuer email domain matches with user email domain

                            if (!_issuedTo.FieldExists(CertificateProfileFlags.EmailAddress) || !issuerCert.IssuedTo.EmailAddress.Host.Equals(_issuedTo.EmailAddress.Host, StringComparison.CurrentCultureIgnoreCase))
                                throw new CryptoException("Certificate issuer '" + issuerCert._issuedTo.Name + "' domain must match with user certificate email address domain.");

                            break;

                        default:
                            throw new InvalidCertificateException("Certificate issuer '" + issuerCert._issuedTo.Name + "' doesn't have capability to sign user certificate.");
                    }

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
                    if ((issuerCert._issuedOnUTC > _issuedOnUTC) || (_issuedOnUTC > issuerCert._expiresOnUTC))
                        throw new InvalidCertificateException("Issuer '" + issuerCert._issuedTo.Name + "' certificate was expired during signing certificate for '" + _issuedTo.Name + "'.");

                    break;
            }

            #endregion

            #region check if user cert is expired

            if ((_type == CertificateType.User) && HasExpired())
                throw new InvalidCertificateException("Certificate issued to '" + _issuedTo.Name + "' has expired.");

            #endregion
        }

        public void VerifyRevocationList(NetProxy proxy = null, int timeout = 10000)
        {
            if (_revocationUri != null)
            {
                bool revoked = false;
                RevocationCertificate revokeCert = null;

                try
                {
                    revoked = RevocationCertificate.IsRevoked(this, out revokeCert, proxy, timeout);

                    if (_issuerSignature.SigningCertificate != null)
                        _issuerSignature.SigningCertificate.VerifyRevocationList(proxy, timeout);
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
            ulong currDate = Convert.ToUInt64((DateTime.UtcNow - _epoch).TotalSeconds);
            return (((currDate + 7200) < _issuedOnUTC) || (currDate > _expiresOnUTC)); //adding 7200 sec (2 hr) margin to allow clients with out of sync system clocks to verify recently created cert.
        }

        public bool IsSigned()
        {
            return (_issuerSignature != null);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            Certificate cert = obj as Certificate;

            if (cert == null)
                return false;

            if (_version != cert._version)
                return false;

            if (_type != cert._type)
                return false;

            if (_serialNumber != cert._serialNumber)
                return false;

            if (!_issuedTo.Equals(cert._issuedTo))
                return false;

            if (_capability != cert._capability)
                return false;

            if (_issuedOnUTC != cert._issuedOnUTC)
                return false;

            if (_expiresOnUTC != cert._expiresOnUTC)
                return false;

            if (_publicKeyEncryptionAlgorithm != cert._publicKeyEncryptionAlgorithm)
                return false;

            if (_publicKeyXML != cert._publicKeyXML)
                return false;

            if (_issuerSignature == cert._issuerSignature)
                return true;

            return _issuerSignature.Equals(cert._issuerSignature);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public byte[] GetHash(string hashAlgorithm)
        {
            if (hashAlgorithm == _lastHashAlgo)
                return _lastHash;

            using (MemoryStream mS = new MemoryStream())
            {
                WriteCertificateTo(mS);
                mS.Position = 0;

                _lastHashAlgo = hashAlgorithm;
                _lastHash = HashAlgorithm.Create(hashAlgorithm).ComputeHash(mS);

                return _lastHash;
            }
        }

        public void WriteTo(Stream s)
        {
            WriteCertificateTo(s);

            if (_issuerSignature == null)
            {
                s.WriteByte((byte)0);
            }
            else
            {
                s.WriteByte((byte)1);
                _issuerSignature.WriteTo(s);
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
        { get { return _epoch.AddSeconds(_issuedOnUTC); } }

        public DateTime ExpiresOnUTC
        { get { return _epoch.AddSeconds(_expiresOnUTC); } }

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