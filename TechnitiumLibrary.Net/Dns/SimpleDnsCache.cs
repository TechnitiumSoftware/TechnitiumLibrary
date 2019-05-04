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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

namespace TechnitiumLibrary.Net.Dns
{
    public class SimpleDnsCache : IDnsCache
    {
        #region variables

        const uint DEFAULT_RECORD_TTL = 60u;
        const uint MINIMUM_RECORD_TTL = 10u;

        readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new ConcurrentDictionary<string, DnsCacheEntry>();

        #endregion

        #region private

        private void CacheEntry(string domain, DnsResourceRecordType type, DnsResourceRecord[] records)
        {
            domain = domain.ToLower();

            DnsCacheEntry entry = _cache.GetOrAdd(domain, delegate (string key)
            {
                return new DnsCacheEntry();
            });

            entry.SetRecords(type, records);
        }

        private string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            return null;
        }

        private DnsResourceRecord[] GetRecords(string domain, DnsResourceRecordType type)
        {
            domain = domain.ToLower();

            if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
            {
                DnsResourceRecord[] records = entry.GetRecords(type);
                if (records != null)
                    return records;
            }

            return null;
        }

        private DnsResourceRecord[] GetClosestNameServers(string domain)
        {
            domain = domain.ToLower();

            while (domain != null)
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    DnsResourceRecord[] records = entry.GetRecords(DnsResourceRecordType.NS);
                    if ((records != null) && (records.Length > 0) && (records[0].RDATA is DnsNSRecord))
                        return records;
                }

                domain = GetParentZone(domain);
            }

            return null;
        }

        #endregion

        #region public

        public DnsDatagram Query(DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];

            DnsResourceRecord[] records = GetRecords(question.Name, question.Type);
            if (records != null)
            {
                if (records[0].RDATA is DnsEmptyRecord)
                {
                    DnsResourceRecord[] responseAuthority;
                    DnsResourceRecord authority = (records[0].RDATA as DnsEmptyRecord).Authority;

                    if (authority == null)
                        responseAuthority = new DnsResourceRecord[] { };
                    else
                        responseAuthority = new DnsResourceRecord[] { authority };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                }

                if (records[0].RDATA is DnsNXRecord)
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { (records[0].RDATA as DnsNXRecord).Authority }, new DnsResourceRecord[] { });

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)records.Length, 0, 0), request.Question, records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
            }

            DnsResourceRecord[] nameServers = GetClosestNameServers(question.Name);
            if (nameServers != null)
            {
                List<DnsResourceRecord> glueRecords = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord nameServer in nameServers)
                {
                    string nsDomain = (nameServer.RDATA as DnsNSRecord).NSDomainName;

                    DnsResourceRecord[] glueAs = GetRecords(nsDomain, DnsResourceRecordType.A);
                    if ((glueAs != null) && (glueAs.Length > 0) && (glueAs[0].RDATA is DnsARecord))
                        glueRecords.AddRange(glueAs);

                    DnsResourceRecord[] glueAAAAs = GetRecords(nsDomain, DnsResourceRecordType.AAAA);
                    if ((glueAAAAs != null) && (glueAAAAs.Length > 0) && (glueAAAAs[0].RDATA is DnsAAAARecord))
                        glueRecords.AddRange(glueAAAAs);
                }

                DnsResourceRecord[] additional = glueRecords.ToArray();

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
        }

        public void CacheResponse(DnsDatagram response)
        {
            if (!response.Header.IsResponse)
                return;

            //combine all records in the response
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NameError:
                    if (response.Authority.Length > 0)
                    {
                        DnsResourceRecord authority = response.Authority[0];
                        if (authority.Type == DnsResourceRecordType.SOA)
                        {
                            authority.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsNXRecord(authority));
                                record.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                                CacheEntry(question.Name, question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                    }
                    break;

                case DnsResponseCode.NoError:
                    if (response.Answer.Length > 0)
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            string qName = question.Name;

                            foreach (DnsResourceRecord answer in response.Answer)
                            {
                                if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                                {
                                    allRecords.Add(answer);

                                    switch (answer.Type)
                                    {
                                        case DnsResourceRecordType.CNAME:
                                            qName = (answer.RDATA as DnsCNAMERecord).CNAMEDomainName;
                                            break;

                                        case DnsResourceRecordType.NS:
                                            string nsDomain = (answer.RDATA as DnsNSRecord).NSDomainName;

                                            if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                            {
                                                foreach (DnsResourceRecord record in response.Additional)
                                                {
                                                    if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                                        allRecords.Add(record);
                                                }
                                            }

                                            break;

                                        case DnsResourceRecordType.MX:
                                            string mxExchange = (answer.RDATA as DnsMXRecord).Exchange;

                                            foreach (DnsResourceRecord record in response.Additional)
                                            {
                                                if (mxExchange.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                                    allRecords.Add(record);
                                            }

                                            break;
                                    }
                                }
                            }
                        }
                    }
                    else if (response.Authority.Length > 0)
                    {
                        DnsResourceRecord authority = response.Authority[0];
                        if (authority.Type == DnsResourceRecordType.SOA)
                        {
                            authority.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                            //empty response with authority
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(authority));
                                record.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                                CacheEntry(question.Name, question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                        else
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                foreach (DnsResourceRecord authorityRecord in response.Authority)
                                {
                                    if ((authorityRecord.Type == DnsResourceRecordType.NS) && question.Name.Equals(authorityRecord.Name, StringComparison.OrdinalIgnoreCase) && (authorityRecord.RDATA as DnsNSRecord).NSDomainName.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //empty response from authority name server
                                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(null));
                                        record.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                                        CacheEntry(question.Name, question.Type, new DnsResourceRecord[] { record });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //empty response with no authority
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(null));
                            record.SetExpiry(MINIMUM_RECORD_TTL, 0u);

                            CacheEntry(question.Name, question.Type, new DnsResourceRecord[] { record });
                        }
                    }

                    break;

                default:
                    return; //nothing to do
            }

            if ((response.Question.Length > 0) && ((response.Question[0].Type != DnsResourceRecordType.NS) || (response.Answer.Length == 0)))
            {
                foreach (DnsQuestionRecord question in response.Question)
                {
                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            allRecords.Add(authority);

                            if (authority.Type == DnsResourceRecordType.NS)
                            {
                                string nsDomain = (authority.RDATA as DnsNSRecord).NSDomainName;

                                if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (DnsResourceRecord record in response.Additional)
                                    {
                                        if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                            allRecords.Add(record);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //set expiry for cached records
            foreach (DnsResourceRecord record in allRecords)
                record.SetExpiry(MINIMUM_RECORD_TTL, 0u);

            #region group all records by domain and type

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in allRecords)
            {
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntries;
                string recordName = record.Name.ToLower();

                if (cacheEntries.ContainsKey(recordName))
                {
                    cacheTypeEntries = cacheEntries[recordName];
                }
                else
                {
                    cacheTypeEntries = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    cacheEntries.Add(recordName, cacheTypeEntries);
                }

                List<DnsResourceRecord> cacheRREntries;

                if (cacheTypeEntries.ContainsKey(record.Type))
                {
                    cacheRREntries = cacheTypeEntries[record.Type];
                }
                else
                {
                    cacheRREntries = new List<DnsResourceRecord>();
                    cacheTypeEntries.Add(record.Type, cacheRREntries);
                }

                cacheRREntries.Add(record);
            }

            #endregion

            //add grouped entries into cache
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
            {
                string domain = cacheEntry.Key;

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                {
                    DnsResourceRecordType type = cacheTypeEntry.Key;
                    DnsResourceRecord[] records = cacheTypeEntry.Value.ToArray();

                    CacheEntry(domain, type, records);
                }
            }

            //cache for ANY request
            if (response.Question[0].Type == DnsResourceRecordType.ANY)
                CacheEntry(response.Question[0].Name, DnsResourceRecordType.ANY, response.Answer);
        }

        #endregion

        class DnsCacheEntry
        {
            #region variables

            readonly ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]> _entries = new ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]>();

            #endregion

            #region public

            public void SetRecords(DnsResourceRecordType type, DnsResourceRecord[] records)
            {
                _entries.AddOrUpdate(type, records, delegate (DnsResourceRecordType key, DnsResourceRecord[] oldValue)
                {
                    return records;
                });
            }

            public DnsResourceRecord[] GetRecords(DnsResourceRecordType type)
            {
                if (_entries.TryGetValue(type, out DnsResourceRecord[] records))
                {
                    if (records[0].IsStale)
                        return null;

                    return records;
                }

                if (type != DnsResourceRecordType.NS)
                {
                    if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out records))
                    {
                        if (records[0].IsStale)
                            return null;

                        return records;
                    }
                }

                return null;
            }

            #endregion
        }

        class DnsNXRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsNXRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsNXRecord other = obj as DnsNXRecord;
                if (other == null)
                    return false;

                return _authority.Equals(other._authority);
            }

            public override int GetHashCode()
            {
                return _authority.GetHashCode();
            }

            public override string ToString()
            {
                return _authority.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        class DnsEmptyRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsEmptyRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsEmptyRecord other = obj as DnsEmptyRecord;
                if (other == null)
                    return false;

                return _authority.Equals(other._authority);
            }

            public override int GetHashCode()
            {
                return _authority.GetHashCode();
            }

            public override string ToString()
            {
                return _authority.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }
    }
}
