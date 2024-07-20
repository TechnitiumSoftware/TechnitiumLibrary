/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public class ZoneFile
    {
        #region variables

        readonly static char[] _trimSeperator = new char[] { ' ', '\t' };
        readonly static char[] _popSeperator = new char[] { ' ', '\t', '(', ')', ';' };

        readonly TextReader _tR;

        string _originDomain;
        uint _defaultTtl;

        string _line;
        uint _lineNo;
        bool _multiLine;

        #endregion

        #region constructor

        private ZoneFile(TextReader tR, string originDomain, uint defaultTtl)
        {
            _tR = tR;
            _originDomain = originDomain;
            _defaultTtl = defaultTtl;
        }

        #endregion

        #region static

        public static async Task<List<DnsResourceRecord>> ReadZoneFileFromAsync(string file, string originDomain = null, uint defaultTtl = 0)
        {
            await using (FileStream fS = new FileStream(file, FileMode.Open, FileAccess.Read))
            {
                return await ReadZoneFileFromAsync(new StreamReader(fS), originDomain, defaultTtl);
            }
        }

        public static Task<List<DnsResourceRecord>> ReadZoneFileFromAsync(TextReader tR, string originDomain = null, uint defaultTtl = 0)
        {
            return new ZoneFile(tR, originDomain, defaultTtl).ReadZoneFileFromAsync();
        }

        public static async Task WriteZoneFileToAsync(string file, string originDomain, IReadOnlyCollection<DnsResourceRecord> records, Func<DnsResourceRecord, string> getComments = null)
        {
            await using (FileStream fS = new FileStream(file, FileMode.Create, FileAccess.Write))
            {
                await using (StreamWriter sW = new StreamWriter(fS))
                {
                    await WriteZoneFileToAsync(sW, originDomain, records, getComments);
                }
            }
        }

        public static async Task WriteZoneFileToAsync(TextWriter tW, string originDomain, IReadOnlyCollection<DnsResourceRecord> records, Func<DnsResourceRecord, string> getComments = null)
        {
            async Task WriteEntryAsync(DnsResourceRecord record)
            {
                string entry = record.ToZoneFileEntry(originDomain);

                if (getComments is not null)
                {
                    string comments = getComments(record);
                    if (!string.IsNullOrEmpty(comments))
                        entry += "\t\t\t;" + comments;
                }

                await tW.WriteLineAsync(entry);
            }

            await tW.WriteLineAsync("$ORIGIN " + originDomain + ".");

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.SOA)
                {
                    await WriteEntryAsync(record);
                    break;
                }
            }

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.NS)
                    await WriteEntryAsync(record);
            }

            foreach (DnsResourceRecord record in records)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.NS:
                        break;

                    default:
                        await WriteEntryAsync(record);
                        break;
                }
            }
        }

        #endregion

        #region internal

        internal async Task<string> PopDomainAsync()
        {
            string domain = await PopItemAsync();

            if (domain == "@")
            {
                if (_originDomain is null)
                    throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

                return _originDomain;
            }

            if (domain.EndsWith('.'))
                return domain.Substring(0, domain.Length - 1);

            if (_originDomain is null)
                throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

            return domain + "." + _originDomain;
        }

        internal async Task<string> PopItemAsync(bool newEntry = false)
        {
            if (newEntry)
            {
                if (_multiLine)
                {
                    while (true)
                    {
                        _line = _line.TrimStart(_trimSeperator);

                        if (_line.StartsWith(')'))
                        {
                            _multiLine = false;
                            break;
                        }

                        string word = PopWord(ref _line);
                        if (word is null)
                        {
                            _line = await _tR.ReadLineAsync();
                            if (_line is null)
                                return null;
                        }
                    }
                }

                _line = null;
            }

            while (true)
            {
                if (_line is null)
                {
                    _line = await _tR.ReadLineAsync();
                    if (_line is null)
                        return null;

                    _lineNo++;

                    if (newEntry)
                    {
                        if (_line.StartsWith(' ') || _line.StartsWith('\t'))
                            return "";
                    }
                }

                _line = _line.TrimStart(_trimSeperator);

                if (_line.Length == 0)
                {
                    if (!newEntry && !_multiLine)
                        return null;

                    //skip empty line
                    _line = null;
                    continue;
                }

                if (_line.StartsWith(';'))
                {
                    if (!newEntry && !_multiLine)
                        return null;

                    //skip comment line
                    _line = null;
                    continue;
                }

                if (_line.StartsWith('('))
                {
                    _multiLine = true;

                    _line = _line.Substring(1);
                    continue;
                }

                if (_line.StartsWith(')'))
                {
                    _multiLine = false;

                    _line = _line.Substring(1);
                    continue;
                }

                string word = PopWord(ref _line);
                if (word is null)
                {
                    if (!_multiLine)
                        return null;

                    _line = null;
                    continue;
                }

                return word;
            }
        }

        internal async Task<string> PopToEndAsync()
        {
            StringBuilder sb = new StringBuilder(256);

            while (true)
            {
                string item = await PopItemAsync();
                if (string.IsNullOrEmpty(item))
                    break;

                sb.Append(item);
            }

            return sb.ToString();
        }

        internal async Task<Stream> GetRData()
        {
            _line = _line.TrimStart(_trimSeperator);

            if (!_line.StartsWith("\\#"))
                return null;

            string item = await PopItemAsync();

            if (!item.StartsWith("\\#"))
                throw new InvalidOperationException();

            item = await PopItemAsync();
            ushort rdLength = ushort.Parse(item);

            string hex = "";

            while (true)
            {
                item = await PopItemAsync();
                if (string.IsNullOrEmpty(item))
                    break;

                hex += item;
            }

            byte[] data = Convert.FromHexString(hex);

            if (rdLength != data.Length)
                throw new FormatException("Unabled to parse record data: RDLENGTH does not match with the hex data length.");

            MemoryStream mS = new MemoryStream(2 + data.Length);
            {
                DnsDatagram.WriteUInt16NetworkOrder(rdLength, mS);
                mS.Write(data);
                mS.Position = 0;
            }

            return mS;
        }

        #endregion

        #region private

        private async Task<List<DnsResourceRecord>> ReadZoneFileFromAsync()
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            string lastDomain = null;
            uint lastTtl = 0;
            DnsClass lastClass = DnsClass.Unknown;

            do
            {
                string item = await PopItemAsync(true);
                if (item is null)
                    break;

                if (item == "$ORIGIN")
                {
                    _originDomain = await PopDomainAsync();

                    if (!DnsClient.IsDomainNameValid(_originDomain))
                        throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

                    continue;
                }

                if (item == "$TTL")
                {
                    _defaultTtl = uint.Parse(await PopItemAsync());
                    continue;
                }

                if (item == "$INCLUDE")
                    throw new NotSupportedException("The zone file parser does not support $INCLUDE control entry on line # " + _lineNo + ".");

                string domain;

                if (item.Length > 0)
                {
                    domain = item;
                    if (domain == "@")
                    {
                        if (_originDomain is null)
                            throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

                        domain = _originDomain;
                    }
                    else if (domain.EndsWith('.'))
                    {
                        domain = domain.Substring(0, domain.Length - 1);
                    }
                    else
                    {
                        if (_originDomain is null)
                            throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

                        domain += "." + _originDomain;
                    }

                    if (!DnsClient.IsDomainNameValid(domain))
                        throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");
                }
                else
                {
                    //use last RR domain
                    if (lastDomain is null)
                        throw new FormatException("The zone file parser failed to parse 'domain' field on line # " + _lineNo + ".");

                    domain = lastDomain;
                }

                uint ttl = 0;
                DnsClass @class = DnsClass.Unknown;
                DnsResourceRecordType type;
                bool ttlRead = false;
                bool classRead = false;

                item = await PopItemAsync();
                if (item is null)
                    throw new FormatException("The zone file parser failed to parse 'rr' field on line # " + _lineNo + ".");

                do
                {
                    if (!ttlRead && uint.TryParse(item, out ttl))
                    {
                        ttlRead = true;
                    }
                    else if (!classRead && Enum.TryParse(item, true, out @class))
                    {
                        classRead = true;
                    }
                    else if (!classRead && item.StartsWith("CLASS", StringComparison.OrdinalIgnoreCase) && ushort.TryParse(item.AsSpan(5), out ushort valClass))
                    {
                        @class = (DnsClass)valClass;
                        classRead = true;
                    }
                    else if (Enum.TryParse(item, true, out type))
                    {
                        break;
                    }
                    else if (item.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase) && ushort.TryParse(item.AsSpan(4), out ushort valType))
                    {
                        type = (DnsResourceRecordType)valType;
                        break;
                    }
                    else
                    {
                        throw new FormatException("The zone file parser failed to parse 'rr' field on line # " + _lineNo + ".");
                    }

                    item = await PopItemAsync();
                    if (item is null)
                        throw new FormatException("The zone file parser failed to parse 'rr' field on line # " + _lineNo + ".");
                }
                while (true);

                if (!ttlRead)
                {
                    if (_defaultTtl > 0)
                        ttl = _defaultTtl;
                    else
                        ttl = lastTtl;
                }

                if (!classRead)
                {
                    if (lastClass == DnsClass.Unknown)
                        @class = DnsClass.IN;
                    else
                        @class = lastClass;
                }

                DnsResourceRecordData rdata;

                try
                {
                    rdata = await ParseRecordDataAsync(type);
                }
                catch (Exception ex)
                {
                    throw new FormatException("The zone file parser failed to parse 'rdata' field on line # " + _lineNo + ".", ex);
                }

                DnsResourceRecord record = new DnsResourceRecord(domain, type, @class, ttl, rdata);

                string comments = await PopCommentAsync();
                if (!string.IsNullOrEmpty(comments))
                    record.Tag = comments;

                records.Add(record);

                lastDomain = domain;
                lastTtl = ttl;
                lastClass = @class;
            }
            while (true);

            return records;
        }

        private async Task<string> PopCommentAsync()
        {
            while (_line.Length > 0)
            {
                _line = _line.TrimStart(_trimSeperator);

                if (_line.StartsWith(';'))
                    return _line.Substring(1);

                _ = await PopItemAsync();
            }

            return null;
        }

        private static string PopWord(ref string line)
        {
            line = line.TrimStart(_trimSeperator);

            if (line.Length == 0)
                return null;

            if (line.StartsWith('\"'))
            {
                int i = 0;

                do
                {
                    i = line.IndexOf('\"', i + 1);
                    if (i < 0)
                        throw new FormatException("Closing double quotes are missing.");

                    if (line[i - 1] != '\\')
                        break;
                }
                while (true);

                string word = line.Substring(1, i - 1);
                line = line.Substring(i + 1);

                return word;
            }
            else
            {
                int i = line.IndexOfAny(_popSeperator);
                string word;

                if (i < 0)
                {
                    word = line;
                    line = "";
                }
                else
                {
                    word = line.Substring(0, i);
                    line = line.Substring(i);
                }

                return word;
            }
        }

        private async Task<DnsResourceRecordData> ParseRecordDataAsync(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.A:
                    return await DnsARecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.NS:
                    return await DnsNSRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.CNAME:
                    return await DnsCNAMERecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.SOA:
                    return await DnsSOARecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.PTR:
                    return await DnsPTRRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.HINFO:
                    return await DnsHINFORecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.MX:
                    return await DnsMXRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.TXT:
                    return await DnsTXTRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.AAAA:
                    return await DnsAAAARecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.SRV:
                    return await DnsSRVRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.NAPTR:
                    return await DnsNAPTRRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.DNAME:
                    return await DnsDNAMERecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.OPT:
                    throw new InvalidOperationException();

                case DnsResourceRecordType.APL:
                    return await DnsAPLRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.DS:
                    return await DnsDSRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.SSHFP:
                    return await DnsSSHFPRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.RRSIG:
                    return await DnsRRSIGRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.NSEC:
                    return await DnsNSECRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.DNSKEY:
                    return await DnsDNSKEYRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.NSEC3:
                    return await DnsNSEC3RecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.NSEC3PARAM:
                    return await DnsNSEC3PARAMRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.TLSA:
                    return await DnsTLSARecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.ZONEMD:
                    return await DnsZONEMDRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    return await DnsSVCBRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.TSIG:
                    throw new InvalidOperationException();

                case DnsResourceRecordType.URI:
                    return await DnsURIRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.CAA:
                    return await DnsCAARecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.ANAME:
                    return await DnsANAMERecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.FWD:
                    return await DnsForwarderRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.APP:
                    return await DnsApplicationRecordData.FromZoneFileEntryAsync(this);

                case DnsResourceRecordType.ALIAS:
                    return await DnsALIASRecordData.FromZoneFileEntryAsync(this);

                default:
                    return await DnsUnknownRecordData.FromZoneFileEntryAsync(this);
            }
        }

        #endregion
    }
}
