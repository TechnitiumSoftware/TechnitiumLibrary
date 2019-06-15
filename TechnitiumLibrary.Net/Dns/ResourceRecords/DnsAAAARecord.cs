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
using System.Net;
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsAAAARecord : DnsResourceRecordData
    {
        #region variables

        IPAddress _address;

        #endregion

        #region constructor

        public DnsAAAARecord(IPAddress address)
        {
            _address = address;

            if (_address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new DnsClientException("Invalid IP address family.");
        }

        public DnsAAAARecord(Stream s)
            : base(s)
        { }

        public DnsAAAARecord(dynamic jsonResourceRecord)
        {
            _length = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            _address = System.Net.IPAddress.Parse(jsonResourceRecord.data.Value);
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _address = new IPAddress(s.ReadBytes(16));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            s.Write(_address.GetAddressBytes());
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsAAAARecord other = obj as DnsAAAARecord;
            if (other == null)
                return false;

            return this._address.Equals(other._address);
        }

        public override int GetHashCode()
        {
            return _address.GetHashCode();
        }

        public override string ToString()
        {
            return _address.ToString();
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public IPAddress Address
        { get { return _address; } }

        public string IPAddress
        { get { return _address.ToString(); } }

        #endregion
    }
}
