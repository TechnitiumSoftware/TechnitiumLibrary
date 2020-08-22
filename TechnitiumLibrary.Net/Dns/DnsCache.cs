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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsCache : IDnsCache
    {
        #region variables

        const uint FAILURE_RECORD_TTL = 30u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint SERVE_STALE_TTL = 0u;

        readonly uint _failureRecordTtl;
        readonly uint _negativeRecordTtl;
        readonly uint _minimumRecordTtl;
        readonly uint _serveStaleTtl;

        readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new ConcurrentDictionary<string, DnsCacheEntry>();

        #endregion

        #region constructor

        public DnsCache()
            : this(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        { }

        protected DnsCache(uint failureRecordTtl, uint negativeRecordTtl, uint minimumRecordTtl, uint serveStaleTtl)
        {
            _failureRecordTtl = failureRecordTtl;
            _negativeRecordTtl = negativeRecordTtl;
            _minimumRecordTtl = minimumRecordTtl;
            _serveStaleTtl = serveStaleTtl;
        }

        #endregion

        #region protected

        protected virtual void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                DnsCacheEntry entry = _cache.GetOrAdd(resourceRecords[0].Name.ToLower(), delegate (string key)
                {
                    return new DnsCacheEntry();
                });

                entry.SetRecords(resourceRecords[0].Type, resourceRecords);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped entries into cache
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
                {
                    DnsCacheEntry entry = _cache.GetOrAdd(cacheEntry.Key.ToLower(), delegate (string key)
                    {
                        return new DnsCacheEntry();
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                        entry.SetRecords(cacheTypeEntry.Key, cacheTypeEntry.Value);
                }
            }
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            return null;
        }

        private IReadOnlyList<DnsResourceRecord> GetRecords(string domain, DnsResourceRecordType type)
        {
            domain = domain.ToLower();

            if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> records = entry.GetRecords(type);
                if (records != null)
                    return records;
            }

            return null;
        }

        private IReadOnlyList<DnsResourceRecord> GetClosestNameServers(string domain)
        {
            domain = domain.ToLower();

            while (domain != null)
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    IReadOnlyList<DnsResourceRecord> records = entry.GetRecords(DnsResourceRecordType.NS);
                    if ((records != null) && (records.Count > 0) && (records[0].RDATA is DnsNSRecord))
                        return records;
                }

                domain = GetParentZone(domain);
            }

            return null;
        }

        #endregion

        #region public

        public virtual DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            if (serveStale)
                throw new NotImplementedException("SimpleDnsCache does not implement serve stale.");

            DnsQuestionRecord question = request.Question[0];

            IReadOnlyList<DnsResourceRecord> answerRecords = GetRecords(question.Name, question.Type);
            if (answerRecords != null)
            {
                if (answerRecords[0].RDATA is DnsEmptyRecord)
                {
                    DnsResourceRecord[] responseAuthority;
                    DnsResourceRecord authority = (answerRecords[0].RDATA as DnsEmptyRecord).Authority;

                    if (authority == null)
                        responseAuthority = Array.Empty<DnsResourceRecord>();
                    else
                        responseAuthority = new DnsResourceRecord[] { authority };

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, responseAuthority);
                }

                if (answerRecords[0].RDATA is DnsNXRecord)
                {
                    DnsResourceRecord[] responseAuthority;
                    DnsResourceRecord authority = (answerRecords[0].RDATA as DnsNXRecord).Authority;

                    if (authority == null)
                        responseAuthority = Array.Empty<DnsResourceRecord>();
                    else
                        responseAuthority = new DnsResourceRecord[] { authority };

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NameError, request.Question, null, responseAuthority);
                }

                if (answerRecords[0].RDATA is DnsANYRecord)
                {
                    DnsANYRecord anyRR = answerRecords[0].RDATA as DnsANYRecord;
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, anyRR.Records);
                }

                if (answerRecords[0].RDATA is DnsFailureRecord)
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, (answerRecords[0].RDATA as DnsFailureRecord).RCODE, request.Question);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answerRecords);
            }

            string currentZone = question.Name;

            while (currentZone != null)
            {
                IReadOnlyList<DnsResourceRecord> nameServers = GetClosestNameServers(currentZone);
                if (nameServers == null)
                    break;

                List<DnsResourceRecord> glueRecords = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord nameServer in nameServers)
                {
                    string nsDomain = (nameServer.RDATA as DnsNSRecord).NameServer;

                    IReadOnlyList<DnsResourceRecord> glueAs = GetRecords(nsDomain, DnsResourceRecordType.A);
                    if ((glueAs != null) && (glueAs.Count > 0) && (glueAs[0].RDATA is DnsARecord))
                        glueRecords.AddRange(glueAs);

                    IReadOnlyList<DnsResourceRecord> glueAAAAs = GetRecords(nsDomain, DnsResourceRecordType.AAAA);
                    if ((glueAAAAs != null) && (glueAAAAs.Count > 0) && (glueAAAAs[0].RDATA is DnsAAAARecord))
                        glueRecords.AddRange(glueAAAAs);
                }

                if (glueRecords.Count > 0)
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, nameServers, glueRecords);

                currentZone = GetParentZone(currentZone);
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.Refused, request.Question);
        }

        public void CacheResponse(DnsDatagram response)
        {
            if (!response.IsResponse || response.Truncation || (response.Question.Count == 0))
                return; //ineligible response

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NameError:
                    //cache response after this switch
                    break;

                default:
                    //cache as failure record with RCODE
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsFailureRecord(response.RCODE));
                        record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                        CacheRecords(new DnsResourceRecord[] { record });
                    }

                    return;
            }

            //cache only NoError and NameError responses

            //combine all records in the response
            List<DnsResourceRecord> cachableRecords = new List<DnsResourceRecord>();

            //get cachable answer records
            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                    {
                        cachableRecords.Add(answer);

                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                qName = (answer.RDATA as DnsCNAMERecord).Domain;
                                break;

                            case DnsResourceRecordType.NS:
                                string nsDomain = (answer.RDATA as DnsNSRecord).NameServer;

                                if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (DnsResourceRecord record in response.Additional)
                                    {
                                        if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (record.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                    if (IPAddress.IsLoopback((record.RDATA as DnsARecord).Address))
                                                        continue;

                                                    break;

                                                case DnsResourceRecordType.AAAA:
                                                    if (IPAddress.IsLoopback((record.RDATA as DnsAAAARecord).Address))
                                                        continue;

                                                    break;
                                            }

                                            cachableRecords.Add(record);
                                        }
                                    }
                                }

                                break;

                            case DnsResourceRecordType.MX:
                                string mxExchange = (answer.RDATA as DnsMXRecord).Exchange;

                                foreach (DnsResourceRecord record in response.Additional)
                                {
                                    if (mxExchange.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                        cachableRecords.Add(record);
                                }

                                break;
                        }
                    }
                }
            }

            //get cachable authority records
            if (response.Authority.Count > 0)
            {
                DnsResourceRecord authority = response.Authority[0];
                if (authority.Type == DnsResourceRecordType.SOA)
                {
                    authority.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                    if (response.Answer.Count == 0)
                    {
                        //empty response with authority
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase) || (authority.Name.Length == 0))
                            {
                                DnsResourceRecord record = null;

                                switch (response.RCODE)
                                {
                                    case DnsResponseCode.NameError:
                                        record = new DnsResourceRecord(question.Name, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsNXRecord(authority));
                                        break;

                                    case DnsResponseCode.NoError:
                                        record = new DnsResourceRecord(question.Name, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsEmptyRecord(authority));
                                        break;
                                }

                                if (record != null)
                                {
                                    record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                                    CacheRecords(new DnsResourceRecord[] { record });
                                }
                            }
                        }
                    }
                    else
                    {
                        //answer response with authority
                        DnsResourceRecord lastAnswer = response.Answer[response.Answer.Count - 1];
                        if (lastAnswer.Type == DnsResourceRecordType.CNAME)
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase))
                                {
                                    DnsResourceRecord record = null;

                                    switch (response.RCODE)
                                    {
                                        case DnsResponseCode.NameError:
                                            record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsNXRecord(authority));
                                            break;

                                        case DnsResponseCode.NoError:
                                            record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsEmptyRecord(authority));
                                            break;
                                    }

                                    if (record != null)
                                    {
                                        record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                                        CacheRecords(new DnsResourceRecord[] { record });
                                    }

                                    break;
                                }
                            }
                        }
                    }
                }
                else if (authority.Type == DnsResourceRecordType.NS)
                {
                    if (response.Answer.Count == 0)
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            foreach (DnsResourceRecord authorityRecord in response.Authority)
                            {
                                if ((authorityRecord.Type == DnsResourceRecordType.NS) && (authorityRecord.RDATA as DnsNSRecord).NameServer.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                {
                                    //empty response from authority name server that was queried
                                    DnsResourceRecord record = null;

                                    switch (response.RCODE)
                                    {
                                        case DnsResponseCode.NameError:
                                            record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsNXRecord(authority));
                                            break;

                                        case DnsResponseCode.NoError:
                                            record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsEmptyRecord(authority));
                                            break;
                                    }

                                    if (record != null)
                                    {
                                        record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                                        CacheRecords(new DnsResourceRecord[] { record });
                                    }

                                    break;
                                }
                            }
                        }
                    }

                    //cache suitable NS records
                    if ((response.Question[0].Type != DnsResourceRecordType.NS) || (response.Answer.Count == 0))
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            foreach (DnsResourceRecord authorityRecords in response.Authority)
                            {
                                if ((authorityRecords.Type == DnsResourceRecordType.NS) && (question.Name.Equals(authorityRecords.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authorityRecords.Name, StringComparison.OrdinalIgnoreCase)))
                                {
                                    cachableRecords.Add(authorityRecords);

                                    string nsDomain = (authorityRecords.RDATA as DnsNSRecord).NameServer;
                                    if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                    {
                                        foreach (DnsResourceRecord record in response.Additional)
                                        {
                                            if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                            {
                                                switch (record.Type)
                                                {
                                                    case DnsResourceRecordType.A:
                                                        if (IPAddress.IsLoopback((record.RDATA as DnsARecord).Address))
                                                            continue;

                                                        break;

                                                    case DnsResourceRecordType.AAAA:
                                                        if (IPAddress.IsLoopback((record.RDATA as DnsAAAARecord).Address))
                                                            continue;

                                                        break;
                                                }

                                                cachableRecords.Add(record);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                //no authority records
                if (response.Answer.Count == 0)
                {
                    //empty response with no authority
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = null;

                        switch (response.RCODE)
                        {
                            case DnsResponseCode.NameError:
                                record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsNXRecord(null));
                                break;

                            case DnsResponseCode.NoError:
                                record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsEmptyRecord(null));
                                break;
                        }

                        if (record != null)
                        {
                            record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                            CacheRecords(new DnsResourceRecord[] { record });
                        }
                    }
                }
            }

            //cache for ANY request
            if (response.RCODE == DnsResponseCode.NoError)
            {
                if ((response.Question.Count == 1) && (response.Question[0].Type == DnsResourceRecordType.ANY))
                {
                    DnsResourceRecord record = new DnsResourceRecord(response.Question[0].Name, DnsResourceRecordType.ANY, response.Question[0].Class, _negativeRecordTtl, new DnsANYRecord(response.Answer));
                    record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                    CacheRecords(new DnsResourceRecord[] { record });
                }
                else
                {
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        if (question.Type == DnsResourceRecordType.ANY)
                        {
                            List<DnsResourceRecord> answerRecords = new List<DnsResourceRecord>();

                            foreach (DnsResourceRecord answerRecord in response.Answer)
                            {
                                if (answerRecord.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                                    answerRecords.Add(answerRecord);
                            }

                            DnsResourceRecord record = new DnsResourceRecord(question.Name, DnsResourceRecordType.ANY, question.Class, _negativeRecordTtl, new DnsANYRecord(answerRecords));
                            record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                            CacheRecords(new DnsResourceRecord[] { record });
                        }
                    }
                }
            }

            if (cachableRecords.Count < 1)
                return; //nothing to cache

            //set expiry for cached records
            foreach (DnsResourceRecord record in cachableRecords)
                record.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

            CacheRecords(cachableRecords);
        }

        #endregion

        public class DnsNXRecord : DnsResourceRecordData
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
                if (obj is null)
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
                return _authority?.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        public class DnsEmptyRecord : DnsResourceRecordData
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
                if (obj is null)
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
                return _authority?.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        public class DnsANYRecord : DnsResourceRecordData
        {
            #region variables

            readonly IReadOnlyList<DnsResourceRecord> _records;

            #endregion

            #region constructor

            public DnsANYRecord(IReadOnlyList<DnsResourceRecord> records)
            {
                _records = records;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            public override string ToString()
            {
                return "[MultipleRecords: " + _records.Count + "]";
            }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsANYRecord other = obj as DnsANYRecord;
                if (other == null)
                    return false;

                return true;
            }

            public override int GetHashCode()
            {
                return 0;
            }

            #endregion

            #region properties

            public IReadOnlyList<DnsResourceRecord> Records
            { get { return _records; } }

            #endregion
        }

        public class DnsFailureRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResponseCode _rcode;

            #endregion

            #region constructor

            public DnsFailureRecord(DnsResponseCode rcode)
            {
                _rcode = rcode;
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
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsFailureRecord other = obj as DnsFailureRecord;
                if (other == null)
                    return false;

                return this._rcode == other._rcode;
            }

            public override int GetHashCode()
            {
                return _rcode.GetHashCode();
            }

            public override string ToString()
            {
                return _rcode.ToString();
            }

            #endregion

            #region properties

            public DnsResponseCode RCODE
            { get { return _rcode; } }

            #endregion
        }

        class DnsCacheEntry
        {
            #region variables

            readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>();

            #endregion

            #region public

            public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
            {
                _entries.AddOrUpdate(type, records, delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> oldValue)
                {
                    return records;
                });
            }

            public IReadOnlyList<DnsResourceRecord> GetRecords(DnsResourceRecordType type)
            {
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records))
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
