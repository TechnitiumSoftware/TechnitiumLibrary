/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsANAMERecord : DnsResourceRecordData
    {
        #region variables

        string _anameDomainName;

        #endregion

        #region constructor

        public DnsANAMERecord(string anameDomainName)
        {
            DnsClient.IsDomainNameValid(anameDomainName, true);

            _anameDomainName = anameDomainName;
        }

        public DnsANAMERecord(Stream s)
            : base(s)
        { }

        public DnsANAMERecord(dynamic jsonResourceRecord)
        {
            _length = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            _anameDomainName = (jsonResourceRecord.data.Value as string).TrimEnd('.');
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _anameDomainName = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            //do not compress domain name so that clients that do not understand ANAME can skip to parsing next record
            DnsDatagram.SerializeDomainName(_anameDomainName, s, null);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsANAMERecord other = obj as DnsANAMERecord;
            if (other == null)
                return false;

            return this._anameDomainName.Equals(other._anameDomainName, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return _anameDomainName.GetHashCode();
        }

        public override string ToString()
        {
            return _anameDomainName + ".";
        }

        #endregion

        #region properties

        public string ANAMEDomainName
        { get { return _anameDomainName; } }

        #endregion
    }
}
