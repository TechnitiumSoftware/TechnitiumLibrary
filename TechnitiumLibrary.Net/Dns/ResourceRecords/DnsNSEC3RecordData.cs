/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnssecNSEC3HashAlgorithm : byte
    {
        Unknown = 0,
        SHA1 = 1
    }

    [Flags]
    public enum DnssecNSEC3Flags : byte
    {
        None = 0,
        OptOut = 1
    }

    //DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
    //https://datatracker.ietf.org/doc/html/rfc5155

    //Authenticated Denial of Existence in the DNS 
    //https://datatracker.ietf.org/doc/html/rfc7129

    public class DnsNSEC3RecordData : DnsResourceRecordData
    {
        #region variables

        DnssecNSEC3HashAlgorithm _hashAlgorithm;
        DnssecNSEC3Flags _flags;
        ushort _iterations;
        byte[] _salt;
        byte[] _nextHashedOwnerNameValue;
        IReadOnlyList<DnsResourceRecordType> _types;

        string _nextHashedOwnerName;
        bool _isInsecureDelegation;
        bool _isAncestorDelegation;
        bool _isAncestorDNAME;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm hashAlgorithm, DnssecNSEC3Flags flags, ushort iterations, byte[] salt, byte[] nextHashedOwnerName, IReadOnlyList<DnsResourceRecordType> types)
        {
            _hashAlgorithm = hashAlgorithm;
            _flags = flags;
            _iterations = iterations;
            _salt = salt;
            _nextHashedOwnerNameValue = nextHashedOwnerName;
            _types = types;

            Serialize();
        }

        public DnsNSEC3RecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static string GetNextCloserName(string domain, string closestEncloser)
        {
            if (domain.Length <= closestEncloser.Length)
                throw new InvalidOperationException();

            string[] labels = domain.Split('.');
            string nextCloserName = null;

            for (int i = 0; i < labels.Length; i++)
            {
                if (nextCloserName is null)
                    nextCloserName = labels[labels.Length - 1 - i];
                else
                    nextCloserName = labels[labels.Length - 1 - i] + "." + nextCloserName;

                if (nextCloserName.Length > closestEncloser.Length)
                    break;
            }

            return nextCloserName;
        }

        public static byte[] GetHashedOwnerNameFrom(string domain)
        {
            return Base32.FromBase32HexString(GetHashedOwnerNameBase32HexStringFrom(domain));
        }

        #endregion

        #region private

        internal static async Task<DnssecProofOfNonExistence> GetValidatedProofOfNonExistenceAsync(IReadOnlyList<DnsResourceRecord> nsec3Records, string domain, DnsResourceRecordType type, bool wildcardAnswerValidation, string wildcardNextCloserName, string wildcardZoneName)
        {
            //find proof for closest encloser
            string closestEncloser;
            string nextCloserName;
            string closestEncloserZoneName;
            bool foundClosestEncloserProof;

            if (wildcardAnswerValidation)
            {
                //wildcard answer case
                //rfc5155#section-7.2.6 - It is not necessary to return an NSEC3 RR that matches the closest encloser, as the existence of this closest encloser is proven by the presence of the expanded wildcard in the response.
                closestEncloser = GetParentZone(wildcardNextCloserName);
                nextCloserName = wildcardNextCloserName;
                closestEncloserZoneName = wildcardZoneName;
                foundClosestEncloserProof = true;
            }
            else
            {
                closestEncloser = domain;
                nextCloserName = null;
                closestEncloserZoneName = null;
                foundClosestEncloserProof = false;
            }

            int maxHashes = DnsClient.NSEC3_MAX_HASHES_PER_SUSPENSION;
            int maxSuspensions = DnsClient.NSEC3_MAX_SUSPENSIONS_PER_RESPONSE;

            while (!foundClosestEncloserProof)
            {
                string hashedClosestEncloser = null;

                foreach (DnsResourceRecord nsec3Record in nsec3Records)
                {
                    if (nsec3Record.Type != DnsResourceRecordType.NSEC3)
                        continue;

                    DnsNSEC3RecordData nsec3 = nsec3Record.RDATA as DnsNSEC3RecordData;
                    if (nsec3.Iterations > DnsClient.MAX_NSEC3_ITERATIONS)
                        return DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue;

                    string nsec3ZoneName = GetHashedOwnerNameZoneNameFrom(nsec3Record.Name);

                    if (hashedClosestEncloser is null)
                    {
                        hashedClosestEncloser = nsec3.ComputeHashedOwnerName(closestEncloser);
                        maxHashes--;

                        if (maxHashes < 1)
                        {
                            maxSuspensions--;

                            if (maxSuspensions < 1)
                                return DnssecProofOfNonExistence.NoProof;

                            //suspend current task by yielding
                            await Task.Yield();

                            maxHashes = DnsClient.NSEC3_MAX_HASHES_PER_SUSPENSION;
                        }
                    }

                    string hashedClosestEncloserDomain = hashedClosestEncloser + (nsec3ZoneName.Length > 0 ? "." + nsec3ZoneName : "");

                    if (nsec3Record.Name.Equals(hashedClosestEncloserDomain, StringComparison.OrdinalIgnoreCase))
                    {
                        //found proof for closest encloser

                        if (closestEncloser.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            //domain matches exactly with closest encloser

                            //check if the NSEC3 is an "ancestor delegation"
                            if ((type != DnsResourceRecordType.DS) && nsec3._isAncestorDelegation)
                                continue; //cannot prove with ancestor delegation NSEC3; try next NSEC3

                            return nsec3.GetProofOfNonExistenceFromRecordTypes(type);
                        }

                        closestEncloserZoneName = nsec3ZoneName;
                        foundClosestEncloserProof = true;
                        break;
                    }
                }

                if (foundClosestEncloserProof)
                    break;

                nextCloserName = closestEncloser;
                closestEncloser = GetParentZone(closestEncloser);
                if (closestEncloser is null)
                    return DnssecProofOfNonExistence.NoProof; //could not find any proof
            }

            //find proof for next closer name
            bool foundNextCloserNameProof = false;
            string hashedNextCloserName = null;

            foreach (DnsResourceRecord nsec3Record in nsec3Records)
            {
                if (nsec3Record.Type != DnsResourceRecordType.NSEC3)
                    continue;

                DnsNSEC3RecordData nsec3 = nsec3Record.RDATA as DnsNSEC3RecordData;
                string nsec3ZoneName = GetHashedOwnerNameZoneNameFrom(nsec3Record.Name);
                string nextHashedOwnerName = nsec3._nextHashedOwnerName + (nsec3ZoneName.Length > 0 ? "." + nsec3ZoneName : "");

                if (hashedNextCloserName is null)
                    hashedNextCloserName = nsec3.ComputeHashedOwnerName(nextCloserName) + (closestEncloserZoneName.Length > 0 ? "." + closestEncloserZoneName : "");

                if (DnsNSECRecordData.IsDomainCovered(nsec3Record.Name, nextHashedOwnerName, hashedNextCloserName))
                {
                    //found proof of cover for hashed next closer name

                    if (nsec3._flags.HasFlag(DnssecNSEC3Flags.OptOut))
                        return DnssecProofOfNonExistence.OptOut;

                    if (nsec3._isAncestorDNAME)
                        return DnssecProofOfNonExistence.NoProof; //An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original) owner name.

                    if (wildcardAnswerValidation)
                        return DnssecProofOfNonExistence.NxDomain; //since wildcard was already validated; the domain does not exists

                    foundNextCloserNameProof = true;
                    break;
                }
            }

            if (!foundNextCloserNameProof)
                return DnssecProofOfNonExistence.NoProof;

            //found next closer name proof; so the domain does not exists but there could be a possibility of wildcard that may exist which also needs to be proved as non-existent

            //find proof for wildcard NXDomain
            string wildcardDomain = closestEncloser.Length > 0 ? "*." + closestEncloser : "*";
            string hashedWildcardDomainName = null;

            foreach (DnsResourceRecord nsec3Record in nsec3Records)
            {
                if (nsec3Record.Type != DnsResourceRecordType.NSEC3)
                    continue;

                DnsNSEC3RecordData nsec3 = nsec3Record.RDATA as DnsNSEC3RecordData;
                string nsec3ZoneName = GetHashedOwnerNameZoneNameFrom(nsec3Record.Name);
                string nextHashedOwnerName = nsec3._nextHashedOwnerName + (nsec3ZoneName.Length > 0 ? "." + nsec3ZoneName : "");

                if (hashedWildcardDomainName is null)
                    hashedWildcardDomainName = nsec3.ComputeHashedOwnerName(wildcardDomain) + (closestEncloserZoneName.Length > 0 ? "." + closestEncloserZoneName : "");

                if (nsec3Record.Name.Equals(hashedWildcardDomainName, StringComparison.OrdinalIgnoreCase))
                {
                    //found proof for wildcard domain

                    //check if the NSEC3 is an "ancestor delegation"
                    if ((type != DnsResourceRecordType.DS) && nsec3._isAncestorDelegation)
                        continue; //cannot prove with ancestor delegation NSEC3; try next NSEC3

                    //wildcard domain exists; find if record set exists or no data
                    return nsec3.GetProofOfNonExistenceFromRecordTypes(type);
                }
                else if (DnsNSECRecordData.IsDomainCovered(nsec3Record.Name, nextHashedOwnerName, hashedWildcardDomainName))
                {
                    //found proof of cover for wildcard domain

                    if (nsec3._flags.HasFlag(DnssecNSEC3Flags.OptOut))
                    {
                        //there is opt-out so there could be a wildcard domain
                        //response failed to prove that the domain does not exists since a wildcard MAY exists
                        return DnssecProofOfNonExistence.NoProof;
                    }

                    if (nsec3._isAncestorDNAME)
                        return DnssecProofOfNonExistence.NoProof; //An NSEC or NSEC3 RR with the DNAME bit set MUST NOT be used to assume the nonexistence of any subdomain of that NSEC/NSEC3 RR's (original) owner name.

                    //no opt-out so wildcard domain does not exists
                    //proved that the actual domain does not exists since a wildcard does not exists
                    return DnssecProofOfNonExistence.NxDomain;
                }
            }

            //found no proof
            return DnssecProofOfNonExistence.NoProof;
        }

        private DnssecProofOfNonExistence GetProofOfNonExistenceFromRecordTypes(DnsResourceRecordType checkType)
        {
            if ((checkType == DnsResourceRecordType.DS) && _isInsecureDelegation)
                return DnssecProofOfNonExistence.InsecureDelegation;

            //find if record set exists
            foreach (DnsResourceRecordType type in _types)
            {
                if ((type == checkType) || (type == DnsResourceRecordType.CNAME))
                    return DnssecProofOfNonExistence.RecordSetExists;
            }

            //found no record set
            return DnssecProofOfNonExistence.NoData;
        }

        private static string GetHashedOwnerNameBase32HexStringFrom(string domain)
        {
            int i = domain.IndexOf('.');
            if (i < 0)
                return domain;

            return domain.Substring(0, i);
        }

        private static string GetHashedOwnerNameZoneNameFrom(string domain)
        {
            int i = domain.IndexOf('.');
            if (i < 0)
                return "";

            return domain.Substring(i + 1);
        }

        private static string GetParentZone(string domain)
        {
            if (domain.Length == 0)
                return null; //no parent for root

            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //return root zone
            return string.Empty;
        }

        internal static byte[] ComputeHashedOwnerName(string ownerName, DnssecNSEC3HashAlgorithm hashAlgorithm, ushort iterations, byte[] salt)
        {
            switch (hashAlgorithm)
            {
                case DnssecNSEC3HashAlgorithm.SHA1:
                    byte[] x;

                    using (MemoryStream mS = new MemoryStream(Math.Max(ownerName.Length, SHA1.HashSizeInBytes)))
                    {
                        DnsDatagram.SerializeDomainName(ownerName.ToLowerInvariant(), mS);
                        mS.Write(salt);

                        mS.Position = 0;
                        x = SHA1.HashData(mS);

                        for (int i = 0; i < iterations; i++)
                        {
                            mS.SetLength(0);

                            mS.Write(x);
                            mS.Write(salt);

                            mS.Position = 0;
                            x = SHA1.HashData(mS);
                        }
                    }

                    return x;

                default:
                    throw new NotSupportedException("NSEC3 hash algorithm is not supported: " + hashAlgorithm.ToString());
            }
        }

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                mS.WriteByte((byte)_hashAlgorithm);
                mS.WriteByte((byte)_flags);
                DnsDatagram.WriteUInt16NetworkOrder(_iterations, mS);
                mS.WriteByte((byte)_salt.Length);
                mS.Write(_salt);
                mS.WriteByte((byte)_nextHashedOwnerNameValue.Length);
                mS.Write(_nextHashedOwnerNameValue);
                DnsNSECRecordData.WriteTypeBitMapsTo(_types, mS);

                _rData = mS.ToArray();
            }

            _nextHashedOwnerName = Base32.ToBase32HexString(_nextHashedOwnerNameValue);

            CheckForDelegation();
        }

        private void CheckForDelegation()
        {
            bool foundDS = false;
            bool foundSOA = false;
            bool foundNS = false;
            bool foundDNAME = false;

            foreach (DnsResourceRecordType type in _types)
            {
                switch (type)
                {
                    case DnsResourceRecordType.DS:
                        foundDS = true;
                        break;

                    case DnsResourceRecordType.SOA:
                        foundSOA = true;
                        break;

                    case DnsResourceRecordType.NS:
                        foundNS = true;
                        break;

                    case DnsResourceRecordType.DNAME:
                        foundDNAME = true;
                        break;
                }
            }

            _isInsecureDelegation = !foundDS && !foundSOA && foundNS;
            _isAncestorDelegation = foundNS && !foundSOA;
            _isAncestorDNAME = foundDNAME;
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _hashAlgorithm = (DnssecNSEC3HashAlgorithm)mS.ReadByteValue();
                _flags = (DnssecNSEC3Flags)mS.ReadByteValue();
                _iterations = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _salt = mS.ReadExactly(mS.ReadByteValue());
                _nextHashedOwnerNameValue = mS.ReadExactly(mS.ReadByteValue());
                _types = DnsNSECRecordData.ReadTypeBitMapsFrom(mS, (int)(mS.Length - mS.Position));
            }

            _nextHashedOwnerName = Base32.ToBase32HexString(_nextHashedOwnerNameValue);

            CheckForDelegation();
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsNSEC3RecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsNSEC3RecordData(rdata);

            DnssecNSEC3HashAlgorithm hashAlgorithm = (DnssecNSEC3HashAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            DnssecNSEC3Flags flags = (DnssecNSEC3Flags)byte.Parse(await zoneFile.PopItemAsync());
            ushort iterations = ushort.Parse(await zoneFile.PopItemAsync());
            byte[] salt;
            {
                string value = await zoneFile.PopItemAsync();
                if (value == "-")
                    salt = Array.Empty<byte>();
                else
                    salt = Convert.FromHexString(value);
            }

            byte[] nextHashedOwnerName = Base32.FromBase32HexString(await zoneFile.PopItemAsync());

            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>();

            do
            {
                string type = await zoneFile.PopItemAsync();
                if (type is null)
                    break;

                types.Add(Enum.Parse<DnsResourceRecordType>(type, true));
            }
            while (true);

            return new DnsNSEC3RecordData(hashAlgorithm, flags, iterations, salt, nextHashedOwnerName, types);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string str = (byte)_hashAlgorithm + " " + (byte)_flags + " " + _iterations + " " + (_salt.Length == 0 ? "-" : Convert.ToHexString(_salt)) + " " + Base32.ToBase32HexString(_nextHashedOwnerNameValue);

            foreach (DnsResourceRecordType type in _types)
                str += " " + type.ToString();

            return str;
        }

        #endregion

        #region public

        public string ComputeHashedOwnerName(string ownerName)
        {
            return Base32.ToBase32HexString(ComputeHashedOwnerName(ownerName, _hashAlgorithm, _iterations, _salt));
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSEC3RecordData other)
            {
                if (_hashAlgorithm != other._hashAlgorithm)
                    return false;

                if (_flags != other._flags)
                    return false;

                if (_iterations != other._iterations)
                    return false;

                if (!BinaryNumber.Equals(_salt, other._salt))
                    return false;

                if (!BinaryNumber.Equals(_nextHashedOwnerNameValue, other._nextHashedOwnerNameValue))
                    return false;

                if (_types.Count != other._types.Count)
                    return false;

                for (int i = 0; i < _types.Count; i++)
                {
                    if (_types[i] != other._types[i])
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_hashAlgorithm, _flags, _iterations, _salt.GetArrayHashCode(), _nextHashedOwnerNameValue.GetArrayHashCode(), _types);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("HashAlgorithm", _hashAlgorithm.ToString());
            jsonWriter.WriteString("Flags", _flags.ToString());
            jsonWriter.WriteNumber("Iterations", _iterations);
            jsonWriter.WriteString("Salt", Convert.ToHexString(_salt));
            jsonWriter.WriteString("NextHashedOwnerName", _nextHashedOwnerName);

            jsonWriter.WritePropertyName("Types");
            jsonWriter.WriteStartArray();

            foreach (DnsResourceRecordType type in _types)
                jsonWriter.WriteStringValue(type.ToString());

            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnssecNSEC3HashAlgorithm HashAlgorithm
        { get { return _hashAlgorithm; } }

        public DnssecNSEC3Flags Flags
        { get { return _flags; } }

        public ushort Iterations
        { get { return _iterations; } }

        public byte[] Salt
        { get { return _salt; } }

        public string NextHashedOwnerName
        { get { return _nextHashedOwnerName; } }

        public byte[] NextHashedOwnerNameValue
        { get { return _nextHashedOwnerNameValue; } }

        public IReadOnlyList<DnsResourceRecordType> Types
        { get { return _types; } }

        public override int UncompressedLength
        { get { return _rData.Length; } }

        #endregion
    }
}
