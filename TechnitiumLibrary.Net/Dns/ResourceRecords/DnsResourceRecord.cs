/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnsResourceRecordType : ushort
    {
        Unknown = 0,
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        NSAP = 22,
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        PX = 26,
        GPOS = 27,
        AAAA = 28,
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        A6 = 38,
        DNAME = 39,
        SINK = 40,
        OPT = 41,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        SMIMEA = 53,
        HIP = 55,
        NINFO = 56,
        RKEY = 57,
        TALINK = 58,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        ZONEMD = 63,
        SVCB = 64,
        HTTPS = 65,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        NID = 104,
        L32 = 105,
        L64 = 106,
        LP = 107,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        IXFR = 251,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255,
        URI = 256,
        CAA = 257,
        AVC = 258,
        TA = 32768,
        DLV = 32769,
        ANAME = 65280, //private use - draft-ietf-dnsop-aname-04
        FWD = 65281, //private use - conditional forwarder
        APP = 65282, //private use - application
    }

    public enum DnsClass : ushort
    {
        IN = 1, //the Internet
        CS = 2, //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, //the CHAOS class
        HS = 4, //Hesiod

        NONE = 254,
        ANY = 255
    }

    public enum DnssecStatus
    {
        Unknown = 0,
        Disabled = 1,
        Secure = 2,
        Insecure = 3,
        Bogus = 4,
        Indeterminate = 5
    }

    public sealed class DnsResourceRecord : IComparable<DnsResourceRecord>
    {
        #region variables

        string _name;
        readonly DnsResourceRecordType _type;
        readonly DnsClass _class;
        uint _ttl;
        readonly DnsResourceRecordData _rData;

        readonly int _datagramOffset;
        bool _setExpiry;
        bool _wasExpiryReset;
        DateTime _ttlExpires;
        DateTime _serveStaleTtlExpires;
        DnssecStatus _dnssecStatus;

        #endregion

        #region constructor

        public DnsResourceRecord(string name, DnsResourceRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData rData)
        {
            DnsClient.IsDomainNameValid(name, true);

            _name = name;
            _type = type;
            _class = @class;
            _ttl = ttl;
            _rData = rData;
        }

        public DnsResourceRecord(Stream s)
        {
            _datagramOffset = Convert.ToInt32(s.Position);

            _name = DnsDatagram.DeserializeDomainName(s);
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
            _ttl = DnsDatagram.ReadUInt32NetworkOrder(s);

            switch (_type)
            {
                case DnsResourceRecordType.A:
                    _rData = new DnsARecordData(s);
                    break;

                case DnsResourceRecordType.NS:
                    _rData = new DnsNSRecordData(s);
                    break;

                case DnsResourceRecordType.CNAME:
                    _rData = new DnsCNAMERecordData(s);
                    break;

                case DnsResourceRecordType.SOA:
                    _rData = new DnsSOARecordData(s);
                    break;

                case DnsResourceRecordType.PTR:
                    _rData = new DnsPTRRecordData(s);
                    break;

                case DnsResourceRecordType.HINFO:
                    _rData = new DnsHINFORecordData(s);
                    break;

                case DnsResourceRecordType.MX:
                    _rData = new DnsMXRecordData(s);
                    break;

                case DnsResourceRecordType.TXT:
                    _rData = new DnsTXTRecordData(s);
                    break;

                case DnsResourceRecordType.AAAA:
                    _rData = new DnsAAAARecordData(s);
                    break;

                case DnsResourceRecordType.SRV:
                    _rData = new DnsSRVRecordData(s);
                    break;

                case DnsResourceRecordType.DNAME:
                    _rData = new DnsDNAMERecordData(s);
                    break;

                case DnsResourceRecordType.OPT:
                    _rData = new DnsOPTRecordData(s);
                    break;

                case DnsResourceRecordType.DS:
                    _rData = new DnsDSRecordData(s);
                    break;

                case DnsResourceRecordType.SSHFP:
                    _rData = new DnsSSHFPRecordData(s);
                    break;

                case DnsResourceRecordType.RRSIG:
                    _rData = new DnsRRSIGRecordData(s);
                    break;

                case DnsResourceRecordType.NSEC:
                    _rData = new DnsNSECRecordData(s);
                    break;

                case DnsResourceRecordType.DNSKEY:
                    _rData = new DnsDNSKEYRecordData(s);
                    break;

                case DnsResourceRecordType.NSEC3:
                    _rData = new DnsNSEC3RecordData(s);
                    break;

                case DnsResourceRecordType.NSEC3PARAM:
                    _rData = new DnsNSEC3PARAMRecordData(s);
                    break;

                case DnsResourceRecordType.TLSA:
                    _rData = new DnsTLSARecordData(s);
                    break;

                case DnsResourceRecordType.TSIG:
                    _rData = new DnsTSIGRecordData(s);
                    break;

                case DnsResourceRecordType.CAA:
                    _rData = new DnsCAARecordData(s);
                    break;

                case DnsResourceRecordType.ANAME:
                    _rData = new DnsANAMERecordData(s);
                    break;

                case DnsResourceRecordType.FWD:
                    _rData = new DnsForwarderRecordData(s);
                    break;

                case DnsResourceRecordType.APP:
                    _rData = new DnsApplicationRecordData(s);
                    break;

                default:
                    _rData = new DnsUnknownRecordData(s);
                    break;
            }
        }

        #endregion

        #region static

        public static Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> GroupRecords(IReadOnlyCollection<DnsResourceRecord> records, bool deduplicate = false)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in records)
            {
                string recordName = record.Name.ToLowerInvariant();

                if (!groupedByDomainRecords.TryGetValue(recordName, out Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> groupedByTypeRecords))
                {
                    groupedByTypeRecords = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    groupedByDomainRecords.Add(recordName, groupedByTypeRecords);
                }

                if (!groupedByTypeRecords.TryGetValue(record.Type, out List<DnsResourceRecord> groupedRecords))
                {
                    groupedRecords = new List<DnsResourceRecord>();
                    groupedByTypeRecords.Add(record.Type, groupedRecords);
                }

                if (deduplicate)
                {
                    if (!groupedRecords.Contains(record))
                        groupedRecords.Add(record);
                }
                else
                {
                    groupedRecords.Add(record);
                }
            }

            return groupedByDomainRecords;
        }

        public static bool IsRRSetExpired(IReadOnlyCollection<DnsResourceRecord> records, bool serveStale)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsExpired(serveStale))
                    return true;
            }

            return false;
        }

        public static bool IsRRSetStale(IReadOnlyCollection<DnsResourceRecord> records)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    return true;
            }

            return false;
        }

        #endregion

        #region internal

        internal void NormalizeName()
        {
            _name = _name.ToLowerInvariant();
            _rData.NormalizeName();
        }

        internal void SetDnssecStatus(DnssecStatus dnssecStatus, bool force = false)
        {
            if ((_dnssecStatus == DnssecStatus.Unknown) || force)
                _dnssecStatus = dnssecStatus;
        }

        internal void FixNameForNSEC(string wildcardName)
        {
            if (_type != DnsResourceRecordType.NSEC)
                throw new InvalidOperationException();

            _name = wildcardName;
        }

        #endregion

        #region public

        public void SetExpiry(uint minimumTtl, uint maximumTtl, uint serveStaleTtl)
        {
            if (_ttl < minimumTtl)
                _ttl = minimumTtl; //to help keep record in cache for a minimum time
            else if (_ttl > maximumTtl)
                _ttl = maximumTtl; //to help remove record from cache early

            _setExpiry = true;
            _wasExpiryReset = false;
            _ttlExpires = DateTime.UtcNow.AddSeconds(_ttl);
            _serveStaleTtlExpires = _ttlExpires.AddSeconds(serveStaleTtl);
        }

        public void ResetExpiry(int seconds)
        {
            if (!_setExpiry)
                throw new InvalidOperationException("Must call SetExpiry() before ResetExpiry().");

            _wasExpiryReset = true;
            _ttlExpires = DateTime.UtcNow.AddSeconds(seconds);
        }

        public void RemoveExpiry()
        {
            _setExpiry = false;
        }

        public bool IsExpired(bool serveStale)
        {
            if (serveStale)
                return TTL < 1u;

            return IsStale;
        }

        public void WriteTo(Stream s)
        {
            WriteTo(s, null);
        }

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.SerializeDomainName(_name, s, domainEntries);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
            DnsDatagram.WriteUInt32NetworkOrder(TTL, s);

            _rData.WriteTo(s, domainEntries);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsResourceRecord other)
            {
                if (!_name.Equals(other._name, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_type != other._type)
                    return false;

                if (_class != other._class)
                    return false;

                if (_ttl != other._ttl)
                    return false;

                return _rData.Equals(other._rData);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_name, _type, _class, _ttl, _rData);
        }

        public int CompareTo(DnsResourceRecord other)
        {
            int value;

            value = DnsNSECRecordData.CanonicalComparison(_name, other._name);
            if (value != 0)
                return value;

            value = _type.CompareTo(other._type);
            if (value != 0)
                return value;

            return _ttl.CompareTo(other._ttl);
        }

        public override string ToString()
        {
            return _name.ToLowerInvariant() + ". " + _type.ToString() + " " + _class.ToString() + " " + _ttl + " " + _rData.ToString();
        }

        public void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Name", _name);
            jsonWriter.WriteString("Type", _type.ToString());
            jsonWriter.WriteString("Class", _class.ToString());

            if (_setExpiry)
            {
                DateTime utcNow = DateTime.UtcNow;
                int ttl;

                if (utcNow > _ttlExpires)
                    ttl = 0;
                else
                    ttl = Convert.ToInt32((_ttlExpires - utcNow).TotalSeconds);

                jsonWriter.WriteString("TTL", ttl + " (" + WebUtilities.GetFormattedTime(ttl) + ")");
            }
            else
            {
                jsonWriter.WriteString("TTL", _ttl + " (" + WebUtilities.GetFormattedTime((int)_ttl) + ")");
            }

            jsonWriter.WriteString("RDLENGTH", _rData.RDLENGTH + " bytes");

            jsonWriter.WritePropertyName("RDATA");
            _rData.SerializeTo(jsonWriter);

            jsonWriter.WriteString("DnssecStatus", _dnssecStatus.ToString());

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        public uint TTL
        {
            get
            {
                if (_setExpiry)
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (utcNow > _serveStaleTtlExpires)
                        return 0u;

                    if (utcNow > _ttlExpires)
                        return 30u; //stale TTL

                    return Convert.ToUInt32((_ttlExpires - utcNow).TotalSeconds);
                }

                return _ttl;
            }
        }

        public bool IsStale
        {
            get
            {
                if (_setExpiry)
                    return DateTime.UtcNow > _ttlExpires;

                return false;
            }
        }

        public bool WasExpiryReset
        { get { return _wasExpiryReset; } }

        public uint OriginalTtlValue
        { get { return _ttl; } }

        public DnsResourceRecordData RDATA
        { get { return _rData; } }

        public int DatagramOffset
        { get { return _datagramOffset; } }

        public ushort UncompressedLength
        { get { return Convert.ToUInt16(DnsDatagram.GetSerializeDomainNameLength(_name) + 2 + 2 + 4 + 2 + _rData.UncompressedLength); } }

        public object Tag { get; set; }

        public DnssecStatus DnssecStatus
        { get { return _dnssecStatus; } }

        #endregion
    }
}
