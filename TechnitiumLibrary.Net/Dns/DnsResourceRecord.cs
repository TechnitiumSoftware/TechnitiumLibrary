/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns
{
    public enum DnsResourceRecordType : ushort
    {
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
        DLV = 32769
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

    public class DnsResourceRecord : IComparable<DnsResourceRecord>
    {
        #region variables

        readonly string _name;
        readonly DnsResourceRecordType _type;
        readonly DnsClass _class;
        uint _ttl;
        readonly DnsResourceRecordData _data;

        bool _setExpiry = false;
        DateTime _ttlExpires;
        DateTime _serveStaleTtlExpires;

        #endregion

        #region constructor

        public DnsResourceRecord(string name, DnsResourceRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData data)
        {
            DnsClient.IsDomainNameValid(name, true);

            _name = name.ToLower();
            _type = type;
            _class = @class;
            _ttl = ttl;
            _data = data;
        }

        public DnsResourceRecord(Stream s)
        {
            _name = DnsDatagram.DeserializeDomainName(s);
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
            _ttl = DnsDatagram.ReadUInt32NetworkOrder(s);

            switch (_type)
            {
                case DnsResourceRecordType.A:
                    _data = new DnsARecord(s);
                    break;

                case DnsResourceRecordType.NS:
                    _data = new DnsNSRecord(s);
                    break;

                case DnsResourceRecordType.CNAME:
                    _data = new DnsCNAMERecord(s);
                    break;

                case DnsResourceRecordType.SOA:
                    _data = new DnsSOARecord(s);
                    break;

                case DnsResourceRecordType.PTR:
                    _data = new DnsPTRRecord(s);
                    break;

                case DnsResourceRecordType.MX:
                    _data = new DnsMXRecord(s);
                    break;

                case DnsResourceRecordType.TXT:
                    _data = new DnsTXTRecord(s);
                    break;

                case DnsResourceRecordType.AAAA:
                    _data = new DnsAAAARecord(s);
                    break;

                case DnsResourceRecordType.SRV:
                    _data = new DnsSRVRecord(s);
                    break;

                default:
                    _data = new DnsUnknownRecord(s);
                    break;
            }
        }

        public DnsResourceRecord(dynamic jsonResourceRecord)
        {
            _name = (jsonResourceRecord.name.Value as string).TrimEnd('.');
            _type = (DnsResourceRecordType)jsonResourceRecord.type;
            _class = DnsClass.IN;
            _ttl = jsonResourceRecord.TTL;

            switch (_type)
            {
                case DnsResourceRecordType.A:
                    _data = new DnsARecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.NS:
                    _data = new DnsNSRecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.CNAME:
                    _data = new DnsCNAMERecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.SOA:
                    _data = new DnsSOARecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.PTR:
                    _data = new DnsPTRRecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.MX:
                    _data = new DnsMXRecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.TXT:
                    _data = new DnsTXTRecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.AAAA:
                    _data = new DnsAAAARecord(jsonResourceRecord);
                    break;

                case DnsResourceRecordType.SRV:
                    _data = new DnsSRVRecord(jsonResourceRecord);
                    break;

                default:
                    _data = new DnsUnknownRecord(jsonResourceRecord);
                    break;
            }
        }

        #endregion

        #region static

        public static Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> GroupRecords(ICollection<DnsResourceRecord> records)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in records)
            {
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> groupedByTypeRecords;
                string recordName = record.Name.ToLower();

                if (groupedByDomainRecords.ContainsKey(recordName))
                {
                    groupedByTypeRecords = groupedByDomainRecords[recordName];
                }
                else
                {
                    groupedByTypeRecords = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    groupedByDomainRecords.Add(recordName, groupedByTypeRecords);
                }

                List<DnsResourceRecord> groupedRecords;

                if (groupedByTypeRecords.ContainsKey(record.Type))
                {
                    groupedRecords = groupedByTypeRecords[record.Type];
                }
                else
                {
                    groupedRecords = new List<DnsResourceRecord>();
                    groupedByTypeRecords.Add(record.Type, groupedRecords);
                }

                groupedRecords.Add(record);
            }

            return groupedByDomainRecords;
        }

        #endregion

        #region public

        public void SetExpiry(uint minimumTtl, uint serveStaleTtl)
        {
            if (_ttl < minimumTtl)
                _ttl = minimumTtl; //to help keep record in cache for a minimum time

            _setExpiry = true;
            _ttlExpires = DateTime.UtcNow.AddSeconds(_ttl);
            _serveStaleTtlExpires = _ttlExpires.AddSeconds(serveStaleTtl);
        }

        public void ResetExpiry(int seconds)
        {
            if (!_setExpiry)
                throw new InvalidOperationException("Must call SetExpiry() before ResetExpiry().");

            _ttlExpires = DateTime.UtcNow.AddSeconds(seconds);
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
            DnsDatagram.WriteUInt32NetworkOrder(TtlValue, s);

            _data.WriteTo(s, domainEntries);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsResourceRecord other = obj as DnsResourceRecord;
            if (other == null)
                return false;

            if (!this._name.Equals(other._name, StringComparison.OrdinalIgnoreCase))
                return false;

            if (this._type != other._type)
                return false;

            if (this._class != other._class)
                return false;

            if (this._ttl != other._ttl)
                return false;

            return this._data.Equals(other._data);
        }

        public override int GetHashCode()
        {
            var hashCode = -205127651;
            hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(_name);
            hashCode = hashCode * -1521134295 + _type.GetHashCode();
            hashCode = hashCode * -1521134295 + _class.GetHashCode();
            hashCode = hashCode * -1521134295 + _ttl.GetHashCode();
            hashCode = hashCode * -1521134295 + EqualityComparer<DnsResourceRecordData>.Default.GetHashCode(_data);
            return hashCode;
        }

        public int CompareTo(DnsResourceRecord other)
        {
            int value;

            value = this._name.CompareTo(other._name);
            if (value != 0)
                return value;

            value = this._type.CompareTo(other._type);
            if (value != 0)
                return value;

            return this._ttl.CompareTo(other._ttl);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        [IgnoreDataMember]
        public uint TtlValue
        {
            get
            {
                if (_setExpiry)
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (Convert.ToInt32((_serveStaleTtlExpires - utcNow).TotalSeconds) < 1)
                        return 0u;

                    int ttl = Convert.ToInt32((_ttlExpires - utcNow).TotalSeconds);
                    if (ttl < 1)
                        return 30u;

                    return Convert.ToUInt32(ttl);
                }

                return _ttl;
            }
        }

        [IgnoreDataMember]
        public bool IsStale
        {
            get
            {
                if (_setExpiry)
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (Convert.ToInt32((_serveStaleTtlExpires - utcNow).TotalSeconds) < 1)
                        return true;

                    int ttl = Convert.ToInt32((_ttlExpires - utcNow).TotalSeconds);

                    return ttl < 1;
                }

                return false;
            }
        }

        public string TTL
        {
            get
            {
                int ttl;

                if (_setExpiry)
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (Convert.ToInt32((_serveStaleTtlExpires - utcNow).TotalSeconds) < 1)
                    {
                        ttl = 0;
                    }
                    else
                    {
                        ttl = Convert.ToInt32((_ttlExpires - utcNow).TotalSeconds);
                        if (ttl < 1)
                            ttl = 0;
                    }
                }
                else
                {
                    ttl = Convert.ToInt32(_ttl);
                }

                return ttl + " (" + WebUtilities.GetFormattedTime(ttl) + ")";
            }
        }

        [IgnoreDataMember]
        public uint OriginalTtlValue
        { get { return _ttl; } }

        public string RDLENGTH
        { get { return _data.RDLENGTH + " bytes"; } }

        public DnsResourceRecordData RDATA
        { get { return _data; } }

        [IgnoreDataMember]
        public object Tag { get; set; }

        #endregion
    }
}
