/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.EDnsOptions;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsRRSIGRecordData : DnsResourceRecordData
    {
        #region variables

        DnsResourceRecordType _typeCovered;
        DnssecAlgorithm _algorithm;
        byte _labels;
        uint _originalTtl;
        uint _signatureExpiration;
        uint _signatureInception;
        ushort _keyTag;
        string _signersName;
        byte[] _signature;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsRRSIGRecordData(DnsResourceRecordType typeCovered, DnssecAlgorithm algorithm, byte labels, uint originalTtl, uint signatureExpiration, uint signatureInception, ushort keyTag, string signersName, byte[] signature)
        {
            _typeCovered = typeCovered;
            _algorithm = algorithm;
            _labels = labels;
            _originalTtl = originalTtl;
            _signatureExpiration = signatureExpiration;
            _signatureInception = signatureInception;
            _keyTag = keyTag;
            _signersName = signersName;
            _signature = signature;
        }

        public DnsRRSIGRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static bool IsWildcard(DnsResourceRecord rrsigRecord)
        {
            if (rrsigRecord.RDATA is DnsRRSIGRecordData rrsig)
                return GetLabelCount(rrsigRecord.Name) > rrsig._labels;

            throw new InvalidOperationException();
        }

        public static bool IsWildcard(DnsResourceRecord rrsigRecord, out string nextCloserName)
        {
            if (rrsigRecord.RDATA is DnsRRSIGRecordData rrsig)
            {
                if (GetLabelCount(rrsigRecord.Name) > rrsig._labels)
                {
                    nextCloserName = GetTrimmedDomain(rrsigRecord.Name, rrsig._labels + 1);
                    return true;
                }
                else
                {
                    nextCloserName = null;
                    return false;
                }
            }

            throw new InvalidOperationException();
        }

        public static byte GetLabelCount(string domain)
        {
            if (domain.Length == 0)
                return 0;

            byte count = 0;
            string[] labels = domain.Split('.');

            for (int i = 0; i < labels.Length; i++)
            {
                if ((i == 0) && (labels[i] == "*"))
                    continue; //not counting the leftmost label if it is a wildcard.

                count++;
            }

            return count;
        }

        public static bool TryGetRRSetHash(DnsRRSIGRecordData rrsigRecord, IReadOnlyList<DnsResourceRecord> records, out byte[] hash, out EDnsExtendedDnsErrorCode extendedDnsErrorCode)
        {
            using (MemoryStream mS = new MemoryStream(512))
            {
                //RRSIG_RDATA
                rrsigRecord.WriteTo(mS, false);

                //RR(i) = owner | type | class | TTL | RDATA length | RDATA

                string name;
                {
                    //The number of labels in the RRset owner name MUST be greater than or equal to the value in the RRSIG RR's Labels field.
                    byte labelCount = GetLabelCount(records[0].Name);

                    if (rrsigRecord._labels == labelCount)
                    {
                        //name = fqdn
                        name = records[0].Name.ToLowerInvariant();
                    }
                    else if (rrsigRecord._labels < labelCount)
                    {
                        //name = "*." | the rightmost rrsig_label labels of the fqdn
                        name = GetWildcardDomain(records[0].Name, rrsigRecord._labels).ToLowerInvariant();

                        if (rrsigRecord._typeCovered == DnsResourceRecordType.NSEC)
                        {
                            //wildcard NSEC can be abused by an attacker to serve NXDomain or NoData responses
                            //fix NSEC record owner name to the original wildcard owner name
                            records[0].FixNameForNSEC(name);
                        }
                    }
                    else
                    {
                        //the RRSIG RR did not pass the necessary validation checks and MUST NOT be used to authenticate this RRset.
                        hash = null;
                        extendedDnsErrorCode = EDnsExtendedDnsErrorCode.RRSIGsMissing;
                        return false;
                    }
                }

                List<CanonicallySerializedResourceRecord> rrList = new List<CanonicallySerializedResourceRecord>(records.Count);

                //select and serialize records
                using (MemoryStream rrBuffer = new MemoryStream(512))
                {
                    foreach (DnsResourceRecord record in records)
                        rrList.Add(CanonicallySerializedResourceRecord.Create(name, record.Type, record.Class, rrsigRecord._originalTtl, record.RDATA, rrBuffer));
                }

                //Canonical RR Ordering by sorting RDATA portion of the canonical form of each RR
                rrList.Sort();

                //write sorted RR into main buffer
                foreach (CanonicallySerializedResourceRecord rr in rrList)
                    rr.WriteTo(mS);

                mS.Position = 0;

                //hash
                switch (rrsigRecord._algorithm)
                {
                    case DnssecAlgorithm.RSAMD5:
                        hash = MD5.HashData(mS);
                        break;

                    case DnssecAlgorithm.DSA:
                    case DnssecAlgorithm.RSASHA1:
                    case DnssecAlgorithm.DSA_NSEC3_SHA1:
                    case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                        hash = SHA1.HashData(mS);
                        break;

                    case DnssecAlgorithm.RSASHA256:
                    case DnssecAlgorithm.ECDSAP256SHA256:
                        hash = SHA256.HashData(mS);
                        break;

                    case DnssecAlgorithm.ECDSAP384SHA384:
                        hash = SHA384.HashData(mS);
                        break;

                    case DnssecAlgorithm.RSASHA512:
                        hash = SHA512.HashData(mS);
                        break;

                    default:
                        hash = null;
                        extendedDnsErrorCode = EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm;
                        return false;
                }

                extendedDnsErrorCode = EDnsExtendedDnsErrorCode.Other;
                return true;
            }
        }

        public static HashAlgorithmName GetHashAlgorithmName(DnssecAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                    return HashAlgorithmName.MD5;

                case DnssecAlgorithm.DSA:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.DSA_NSEC3_SHA1:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                    return HashAlgorithmName.SHA1;

                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.ECDSAP256SHA256:
                    return HashAlgorithmName.SHA256;

                case DnssecAlgorithm.ECDSAP384SHA384:
                    return HashAlgorithmName.SHA384;

                case DnssecAlgorithm.RSASHA512:
                    return HashAlgorithmName.SHA512;

                default:
                    throw new NotSupportedException("DNSSEC algorithm is not supported: " + algorithm.ToString());
            }
        }

        #endregion

        #region private

        private static string GetWildcardDomain(string domain, int labelCount)
        {
            return "*." + GetTrimmedDomain(domain, labelCount);
        }

        private static string GetTrimmedDomain(string domain, int labelCount)
        {
            string[] labels = domain.Split('.');
            string trimmedDomain = null;

            for (int i = 0; i < labelCount; i++)
            {
                if (trimmedDomain is null)
                    trimmedDomain = labels[labels.Length - 1 - i];
                else
                    trimmedDomain = labels[labels.Length - 1 - i] + "." + trimmedDomain;
            }

            return trimmedDomain;
        }

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length))
            {
                WriteTo(mS, true);

                _rData = mS.ToArray();
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _typeCovered = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _algorithm = (DnssecAlgorithm)s.ReadByteValue();
            _labels = s.ReadByteValue();
            _originalTtl = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureExpiration = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureInception = DnsDatagram.ReadUInt32NetworkOrder(s);
            _keyTag = DnsDatagram.ReadUInt16NetworkOrder(s);
            _signersName = DnsDatagram.DeserializeDomainName(s);
            _signature = s.ReadExactly(_rdLength - 2 - 1 - 1 - 4 - 4 - 4 - 2 - DnsDatagram.GetSerializeDomainNameLength(_signersName));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
                Serialize();

            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsRRSIGRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsRRSIGRecordData(rdata);

            DnsResourceRecordType typeCovered = Enum.Parse<DnsResourceRecordType>(await zoneFile.PopItemAsync(), true);
            DnssecAlgorithm algorithm = (DnssecAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            byte labels = byte.Parse(await zoneFile.PopItemAsync());
            uint originalTtl = uint.Parse(await zoneFile.PopItemAsync());

            string strSignatureExpiration = await zoneFile.PopItemAsync();
            uint signatureExpiration;
            if (strSignatureExpiration.Length == 14)
                signatureExpiration = Convert.ToUInt32((DateTime.ParseExact(strSignatureExpiration, "yyyyMMddHHmmss", CultureInfo.CurrentCulture) - DateTime.UnixEpoch).TotalSeconds);
            else
                signatureExpiration = uint.Parse(strSignatureExpiration);

            string strSignatureInception = await zoneFile.PopItemAsync();
            uint signatureInception;
            if (strSignatureInception.Length == 14)
                signatureInception = Convert.ToUInt32((DateTime.ParseExact(strSignatureInception, "yyyyMMddHHmmss", CultureInfo.CurrentCulture) - DateTime.UnixEpoch).TotalSeconds);
            else
                signatureInception = uint.Parse(strSignatureInception);

            ushort keyTag = ushort.Parse(await zoneFile.PopItemAsync());
            string signersName = await zoneFile.PopDomainAsync();
            byte[] signature = Convert.FromBase64String(await zoneFile.PopToEndAsync());

            return new DnsRRSIGRecordData(typeCovered, algorithm, labels, originalTtl, signatureExpiration, signatureInception, keyTag, signersName, signature);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return (ushort)_typeCovered + " " + (byte)_algorithm + " " + _labels + " " + _originalTtl + " " + _signatureExpiration + " " + _signatureInception + " " + _keyTag + " " + DnsResourceRecord.GetRelativeDomainName(_signersName, originDomain) + " " + Convert.ToBase64String(_signature);
        }

        #endregion

        #region private

        private void WriteTo(MemoryStream s, bool includeSignature)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_typeCovered, s);
            s.WriteByte((byte)_algorithm);
            s.WriteByte(_labels);
            DnsDatagram.WriteUInt32NetworkOrder(_originalTtl, s);
            DnsDatagram.WriteUInt32NetworkOrder(_signatureExpiration, s);
            DnsDatagram.WriteUInt32NetworkOrder(_signatureInception, s);
            DnsDatagram.WriteUInt16NetworkOrder(_keyTag, s);
            DnsDatagram.SerializeDomainName(_signersName.ToLowerInvariant(), s);

            if (includeSignature)
                s.Write(_signature);
        }

        #endregion

        #region public

        public bool IsSignatureValid(IReadOnlyList<DnsResourceRecord> records, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, ref int maxCryptoFailures, out EDnsExtendedDnsErrorCode extendedDnsErrorCode)
        {
            uint utc = Convert.ToUInt32((DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds % uint.MaxValue);

            //The validator's notion of the current time MUST be less than or equal to the time listed in the RRSIG RR's Expiration field.
            if (DnsSOARecordData.IsZoneUpdateAvailable(_signatureExpiration, utc)) //using Serial number arithmetic
            {
                //utc is greater than expiration; so signature is expired
                extendedDnsErrorCode = EDnsExtendedDnsErrorCode.SignatureExpired;
                return false;
            }

            //The validator's notion of the current time MUST be greater than or equal to the time listed in the RRSIG RR's Inception field.
            if (DnsSOARecordData.IsZoneUpdateAvailable(utc, _signatureInception)) //using Serial number arithmetic
            {
                //inception is greater than utc; so signature is not yet valid
                extendedDnsErrorCode = EDnsExtendedDnsErrorCode.SignatureNotYetValid;
                return false;
            }

            if (!TryGetRRSetHash(this, records, out byte[] hash, out extendedDnsErrorCode))
                return false;

            HashAlgorithmName hashAlgorithm = GetHashAlgorithmName(_algorithm);

            bool foundDnsKey = false;
            bool foundSupportedDnsKeyAlgo = false;
            bool foundZoneKeyBitSet = false;
            bool isBogus = false;

            foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
            {
                if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                //The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST match the owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset.
                if (!dnsKeyRecord.Name.Equals(_signersName, StringComparison.OrdinalIgnoreCase))
                    continue;

                DnsDNSKEYRecordData dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecordData;

                if (dnsKey.Protocol != 3)
                    continue;

                if (dnsKey.Algorithm != _algorithm)
                    continue;

                if (dnsKey.ComputedKeyTag != _keyTag)
                    continue;

                foundDnsKey = true;

                if (!dnsKey.PublicKey.IsAlgorithmSupported)
                    continue;

                foundSupportedDnsKeyAlgo = true;

                //The matching DNSKEY RR MUST be present in the zone's apex DNSKEY RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7) set.
                if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.ZoneKey))
                {
                    foundZoneKeyBitSet = true;

                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke) && (_typeCovered != DnsResourceRecordType.DNSKEY))
                        continue; //rfc5011: the resolver MUST consider this key permanently invalid for all purposes except for validating the revocation.

                    if (dnsKey.PublicKey.IsSignatureValid(hash, _signature, hashAlgorithm))
                    {
                        extendedDnsErrorCode = EDnsExtendedDnsErrorCode.Other; //no error
                        return true;
                    }

                    maxCryptoFailures--;

                    if (maxCryptoFailures < 1)
                    {
                        extendedDnsErrorCode = EDnsExtendedDnsErrorCode.DnssecBogus;
                        return false; //too many crypto failures
                    }

                    isBogus = true;
                }
            }

            if (isBogus)
            {
                extendedDnsErrorCode = EDnsExtendedDnsErrorCode.DnssecBogus;
            }
            else
            {
                if (foundDnsKey)
                {
                    if (foundSupportedDnsKeyAlgo)
                    {
                        if (foundZoneKeyBitSet)
                            extendedDnsErrorCode = EDnsExtendedDnsErrorCode.Other;
                        else
                            extendedDnsErrorCode = EDnsExtendedDnsErrorCode.NoZoneKeyBitSet;
                    }
                    else
                    {
                        extendedDnsErrorCode = EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm;
                    }
                }
                else
                {
                    extendedDnsErrorCode = EDnsExtendedDnsErrorCode.DNSKEYMissing;
                }
            }

            return false;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsRRSIGRecordData other)
            {
                if (_typeCovered != other._typeCovered)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (_labels != other._labels)
                    return false;

                if (_originalTtl != other._originalTtl)
                    return false;

                if (_signatureExpiration != other._signatureExpiration)
                    return false;

                if (_signatureInception != other._signatureInception)
                    return false;

                if (_keyTag != other._keyTag)
                    return false;

                if (!_signersName.Equals(other._signersName, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!BinaryNumber.Equals(_signature, other._signature))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();

            hash.Add(_typeCovered);
            hash.Add(_algorithm);
            hash.Add(_labels);
            hash.Add(_originalTtl);
            hash.Add(_signatureExpiration);
            hash.Add(_signatureInception);
            hash.Add(_keyTag);
            hash.Add(_signersName);
            hash.Add(_signature);

            return hash.ToHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("TypeCovered", _typeCovered.ToString());
            jsonWriter.WriteString("Algorithm", _algorithm.ToString());
            jsonWriter.WriteNumber("Labels", _labels);
            jsonWriter.WriteNumber("OriginalTtl", _originalTtl);
            jsonWriter.WriteString("SignatureExpiration", DateTime.UnixEpoch.AddSeconds(_signatureExpiration));
            jsonWriter.WriteString("SignatureInception", DateTime.UnixEpoch.AddSeconds(_signatureInception));
            jsonWriter.WriteNumber("KeyTag", _keyTag);
            jsonWriter.WriteString("SignersName", _signersName);
            jsonWriter.WriteString("Signature", Convert.ToBase64String(_signature));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsResourceRecordType TypeCovered
        { get { return _typeCovered; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public byte Labels
        { get { return _labels; } }

        public uint OriginalTtl
        { get { return _originalTtl; } }

        public uint SignatureExpiration
        { get { return _signatureExpiration; } }

        public uint SignatureInception
        { get { return _signatureInception; } }

        public ushort KeyTag
        { get { return _keyTag; } }

        public string SignersName
        { get { return _signersName; } }

        public byte[] Signature
        { get { return _signature; } }

        public override int UncompressedLength
        { get { return 2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length; } }

        #endregion
    }
}
