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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.Net.Dns
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

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            byte[] data = new byte[length];
            s.Read(data, 0, length);
            _txtData = Encoding.ASCII.GetString(data, 0, length);
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
            return _txtData;
        }

        #endregion

        #region properties

        public string TXTData
        { get { return _txtData; } }

        #endregion
    }
}
