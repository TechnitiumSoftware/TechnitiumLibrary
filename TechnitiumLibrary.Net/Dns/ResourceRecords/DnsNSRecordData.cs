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
using System.Runtime.Serialization;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsNSRecordData : DnsResourceRecordData
    {
        #region variables

        string _nameServer;

        bool _parentSideTtlExpirySet;
        DateTime _parentSideTtlExpires;
        const uint PARENT_SIDE_NS_MINIMUM_TTL = 3600u; //1 hr to prevent frequent revalidations
        const uint PARENT_SIDE_NS_MAXIMUM_TTL = 86400u; //1 day to revalidate within this limit

        #endregion

        #region constructor

        public DnsNSRecordData(string nameServer)
        {
            DnsClient.IsDomainNameValid(nameServer, true);

            _nameServer = nameServer;
        }

        public DnsNSRecordData(Stream s)
            : base(s)
        { }

        public DnsNSRecordData(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            _nameServer = (jsonResourceRecord.data.Value as string).TrimEnd('.');
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _nameServer = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _nameServer.ToLower() : _nameServer, s, domainEntries);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _nameServer = _nameServer.ToLower();
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSRecordData other)
                return _nameServer.Equals(other._nameServer, StringComparison.OrdinalIgnoreCase);

            return false;
        }

        public override int GetHashCode()
        {
            return _nameServer.GetHashCode();
        }

        public override string ToString()
        {
            return _nameServer.ToLower() + ".";
        }

        #endregion

        #region properties

        public string NameServer
        { get { return _nameServer; } }

        [IgnoreDataMember]
        public uint ParentSideTtl
        {
            get
            {
                if (!_parentSideTtlExpirySet)
                    throw new InvalidOperationException();

                DateTime utcNow = DateTime.UtcNow;

                if (utcNow > _parentSideTtlExpires)
                    return 0u;

                return Convert.ToUInt32((_parentSideTtlExpires - utcNow).TotalSeconds);
            }
            set
            {
                if (_parentSideTtlExpirySet)
                    throw new InvalidOperationException();

                if (value < PARENT_SIDE_NS_MINIMUM_TTL)
                    value = PARENT_SIDE_NS_MINIMUM_TTL;
                else if (value > PARENT_SIDE_NS_MAXIMUM_TTL)
                    value = PARENT_SIDE_NS_MAXIMUM_TTL;

                _parentSideTtlExpires = DateTime.UtcNow.AddSeconds(value);
                _parentSideTtlExpirySet = true;
            }
        }

        [IgnoreDataMember]
        public bool IsParentSideTtlSet
        { get { return _parentSideTtlExpirySet; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(DnsDatagram.GetSerializeDomainNameLength(_nameServer)); } }

        #endregion
    }
}
