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

using System.Collections.Concurrent;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public class SimpleDnsCache : DnsCache
    {
        #region variables

        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint SERVE_STALE_TTL = 0u;

        readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new ConcurrentDictionary<string, DnsCacheEntry>();

        #endregion

        #region constructor

        public SimpleDnsCache()
            : base(NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        { }

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

        #region protected

        protected override void CacheRecords(ICollection<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                foreach (DnsResourceRecord resourceRecord in resourceRecords)
                    CacheEntry(resourceRecord.Name, resourceRecord.Type, new DnsResourceRecord[] { resourceRecord });
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

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
            }
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];

            DnsResourceRecord[] answerRecords = GetRecords(question.Name, question.Type);
            if (answerRecords != null)
            {
                if (answerRecords[0].RDATA is DnsEmptyRecord)
                {
                    DnsResourceRecord[] responseAuthority;
                    DnsResourceRecord authority = (answerRecords[0].RDATA as DnsEmptyRecord).Authority;

                    if (authority == null)
                        responseAuthority = new DnsResourceRecord[] { };
                    else
                        responseAuthority = new DnsResourceRecord[] { authority };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                }

                if (answerRecords[0].RDATA is DnsNXRecord)
                {
                    DnsResourceRecord[] responseAuthority;
                    DnsResourceRecord authority = (answerRecords[0].RDATA as DnsNXRecord).Authority;

                    if (authority == null)
                        responseAuthority = new DnsResourceRecord[] { };
                    else
                        responseAuthority = new DnsResourceRecord[] { authority };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                }

                if (answerRecords[0].RDATA is DnsANYRecord)
                {
                    DnsANYRecord anyRR = answerRecords[0].RDATA as DnsANYRecord;
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)anyRR.Records.Length, 0, 0), request.Question, anyRR.Records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                }

                if (answerRecords[0].RDATA is DnsFailureRecord)
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, (answerRecords[0].RDATA as DnsFailureRecord).RCODE, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)answerRecords.Length, 0, 0), request.Question, answerRecords, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
            }

            string currentZone = question.Name;

            while (currentZone != null)
            {
                DnsResourceRecord[] nameServers = GetClosestNameServers(currentZone);
                if (nameServers == null)
                    break;

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

                if (glueRecords.Count > 0)
                {
                    DnsResourceRecord[] additional = glueRecords.ToArray();
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);
                }

                currentZone = GetParentZone(currentZone);
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
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
    }
}
