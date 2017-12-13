/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

using System.Collections.Generic;
using System.IO;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsNSRecord : DnsResourceRecordData
    {
        #region variables

        string _nsDomainName;

        #endregion

        #region constructor

        public DnsNSRecord(string nsDomainName)
        {
            _nsDomainName = nsDomainName;
        }

        public DnsNSRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _nsDomainName = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_nsDomainName, s, domainEntries);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsNSRecord other = obj as DnsNSRecord;
            if (other == null)
                return false;

            return this._nsDomainName.Equals(other._nsDomainName, System.StringComparison.CurrentCultureIgnoreCase);
        }

        public override int GetHashCode()
        {
            return _nsDomainName.GetHashCode();
        }

        public override string ToString()
        {
            return _nsDomainName;
        }

        #endregion

        #region properties

        public string NSDomainName
        { get { return _nsDomainName; } }

        #endregion
    }
}
