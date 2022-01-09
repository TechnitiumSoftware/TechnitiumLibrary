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
using TechnitiumLibrary.Net.Dns.EDnsOptions;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsOPTRecord : DnsResourceRecordData
    {
        #region variables

        public readonly static DnsOPTRecord Empty = new DnsOPTRecord();

        IReadOnlyList<EDnsOption> _options;

        #endregion

        #region constructors

        public DnsOPTRecord()
        {
            _options = Array.Empty<EDnsOption>();
        }

        public DnsOPTRecord(IReadOnlyList<EDnsOption> options)
        {
            _options = options;
        }

        public DnsOPTRecord(Stream s)
            : base(s)
        { }

        public DnsOPTRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            List<EDnsOption> options = null;
            int bytesRead = 0;

            while (bytesRead < _rdLength)
            {
                EDnsOption option = new EDnsOption(s);

                if (options is null)
                    options = new List<EDnsOption>(1);

                options.Add(option);

                bytesRead += 2 + 2 + option.Data.Length;
            }

            if (options is null)
                _options = Array.Empty<EDnsOption>();
            else
                _options = options;
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            foreach (EDnsOption option in _options)
                option.WriteTo(s);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsOPTRecord other)
            {
                for (int i = 0; i < _options.Count; i++)
                {
                    if (!_options[i].Equals(other._options[i]))
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_options);
        }

        public override string ToString()
        {
            string s = null;

            foreach (EDnsOption option in _options)
            {
                if (s is null)
                    s = option.ToString();
                else
                    s += ", " + option.ToString();
            }

            if (s is not null)
                return s;

            return nameof(DnsOPTRecord);
        }

        #endregion

        #region properties

        public IReadOnlyList<EDnsOption> Options
        { get { return _options; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        {
            get
            {
                ushort length = 0;

                foreach (EDnsOption option in _options)
                    length += option.UncompressedLength;

                return length;
            }
        }

        #endregion
    }
}
