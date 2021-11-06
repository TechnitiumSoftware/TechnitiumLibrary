/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsApplicationRecord : DnsResourceRecordData
    {
        #region variables

        string _appName;
        string _classPath;
        string _data;

        #endregion

        #region constructor

        public DnsApplicationRecord(string appName, string classPath, string data)
        {
            _appName = appName;
            _classPath = classPath;
            _data = data;
        }

        public DnsApplicationRecord(Stream s)
            : base(s)
        { }

        public DnsApplicationRecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(new char[] { ' ' }, 3);

            _appName = parts[0];
            _classPath = parts[1];

            if (parts.Length > 2)
                _data = Encoding.UTF8.GetString(Convert.FromBase64String(parts[2]));
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            using (BinaryReader bR = new BinaryReader(s, Encoding.UTF8, true))
            {
                int version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                        _appName = bR.ReadShortString();
                        _classPath = bR.ReadShortString();
                        _data = bR.ReadString();
                        break;

                    default:
                        throw new NotSupportedException("DNS application record version not supported: " + version);
                }
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            using (BinaryWriter bW = new BinaryWriter(s, Encoding.UTF8, true))
            {
                bW.Write((byte)1); //version
                bW.WriteShortString(_appName);
                bW.WriteShortString(_classPath);
                bW.Write(_data);
            }
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsApplicationRecord other)
            {
                if (!_appName.Equals(other._appName))
                    return false;

                if (!_classPath.Equals(other._classPath))
                    return false;

                return _data.Equals(other._data);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _appName.GetHashCode() ^ _classPath.GetHashCode() ^ _data.GetHashCode();
        }

        public override string ToString()
        {
            return _appName + " " + _classPath + " " + Convert.ToBase64String(Encoding.UTF8.GetBytes(_data));
        }

        #endregion

        #region properties

        public string AppName
        { get { return _appName; } }

        public string ClassPath
        { get { return _classPath; } }

        public string Data
        { get { return _data; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(1 + 1 + _appName.Length + 1 + _classPath.Length + 2 + _data.Length); } }

        #endregion
    }
}
