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
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsTXTRecord : DnsResourceRecordData
    {
        #region variables

        string _txtData;

        #endregion

        #region constructor

        public DnsTXTRecord(string txtData)
        {
            _txtData = txtData;
        }

        public DnsTXTRecord(Stream s)
            : base(s)
        { }

        public DnsTXTRecord(dynamic jsonResourceRecord)
        {
            _length = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            _txtData = DnsDatagram.DecodeCharacterString(jsonResourceRecord.data.Value);
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            _txtData = Encoding.ASCII.GetString(s.ReadBytes(length));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            byte[] data = Encoding.ASCII.GetBytes(_txtData);

            s.WriteByte(Convert.ToByte(data.Length));
            s.Write(data, 0, data.Length);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsTXTRecord other = obj as DnsTXTRecord;
            if (other == null)
                return false;

            return this._txtData.Equals(other._txtData);
        }

        public override int GetHashCode()
        {
            return _txtData.GetHashCode();
        }

        public override string ToString()
        {
            return DnsDatagram.EncodeCharacterString(_txtData);
        }

        #endregion

        #region properties

        public string TXTData
        { get { return _txtData; } }

        #endregion
    }
}
