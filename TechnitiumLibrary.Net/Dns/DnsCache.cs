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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    //Negative Caching of DNS Queries (DNS NCACHE) https://datatracker.ietf.org/doc/html/rfc2308
    public class DnsCache : IDnsCache
    {
        #region variables

        const uint FAILURE_RECORD_TTL = 60u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint MAXIMUM_RECORD_TTL = 3600u;
        const uint SERVE_STALE_TTL = 0u;
        const uint SERVE_STALE_TTL_MAX = 7 * 24 * 60 * 60; //7 days cap on serve stale

        uint _failureRecordTtl;
        uint _negativeRecordTtl;
        uint _minimumRecordTtl;
        uint _maximumRecordTtl;
        uint _serveStaleTtl;

        readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new ConcurrentDictionary<string, DnsCacheEntry>(1, 5);

        #endregion

        #region constructor

        public DnsCache()
            : this(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, MAXIMUM_RECORD_TTL, SERVE_STALE_TTL)
        { }

        protected DnsCache(uint failureRecordTtl, uint negativeRecordTtl, uint minimumRecordTtl, uint maximumRecordTtl, uint serveStaleTtl)
        {
            _failureRecordTtl = failureRecordTtl;
            _negativeRecordTtl = negativeRecordTtl;
            _minimumRecordTtl = minimumRecordTtl;
            _maximumRecordTtl = maximumRecordTtl;
            _serveStaleTtl = serveStaleTtl;
        }

        #endregion

        #region protected

        protected virtual void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                if (resourceRecords[0].Name.Contains('*'))
                    return;

                DnsCacheEntry entry = _cache.GetOrAdd(resourceRecords[0].Name.ToLower(), delegate (string key)
                {
                    return new DnsCacheEntry(1);
                });

                entry.SetRecords(resourceRecords[0].Type, resourceRecords);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped entries into cache
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
                {
                    if (cacheEntry.Key.Contains('*'))
                        continue;

                    DnsCacheEntry entry = _cache.GetOrAdd(cacheEntry.Key.ToLower(), delegate (string key)
                    {
                        return new DnsCacheEntry(cacheEntry.Value.Count);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                        entry.SetRecords(cacheTypeEntry.Key, cacheTypeEntry.Value);
                }
            }
        }

        protected static IReadOnlyList<DnsResourceRecord> GetGlueRecordsFrom(DnsResourceRecord record)
        {
            if (record.Tag is List<DnsResourceRecord> glueRecords)
                return glueRecords;

            return Array.Empty<DnsResourceRecord>();
        }

        #endregion

        #region private

        private static void AddGlueRecordTo(DnsResourceRecord record, DnsResourceRecord glueRecord)
        {
            if (record.Tag is not List<DnsResourceRecord> glueRecords)
            {
                glueRecords = new List<DnsResourceRecord>();
                record.Tag = glueRecords;
            }

            glueRecords.Add(glueRecord);
        }

        private void InternalCacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                resourceRecord.NormalizeName();

                foreach (DnsResourceRecord glueRecord in GetGlueRecordsFrom(resourceRecord))
                    glueRecord.NormalizeName();
            }

            CacheRecords(resourceRecords);
        }

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private IReadOnlyList<DnsResourceRecord> GetClosestNameServers(string domain)
        {
            domain = domain.ToLower();

            do
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.NS, true);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS))
                        return records;
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            return null;
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                if (!_cache.TryGetValue((lastCNAME.RDATA as DnsCNAMERecord).Domain.ToLower(), out DnsCacheEntry entry))
                    break;

                IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(question.Type, true);
                if (records.Count < 1)
                    break;

                answerRecords.AddRange(records);

                if (records[0].Type != DnsResourceRecordType.CNAME)
                    break;

                lastCNAME = records[0];
            }
            while (++queryCount < DnsClient.MAX_CNAME_HOPS);
        }

        private IReadOnlyList<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        DnsNSRecord nsRecord = refRecord.RDATA as DnsNSRecord;
                        if (nsRecord is not null)
                            ResolveAdditionalRecords(refRecord, nsRecord.NameServer, additionalRecords);

                        break;

                    case DnsResourceRecordType.MX:
                        DnsMXRecord mxRecord = refRecord.RDATA as DnsMXRecord;
                        if (mxRecord is not null)
                            ResolveAdditionalRecords(refRecord, mxRecord.Exchange, additionalRecords);

                        break;

                    case DnsResourceRecordType.SRV:
                        DnsSRVRecord srvRecord = refRecord.RDATA as DnsSRVRecord;
                        if (srvRecord is not null)
                            ResolveAdditionalRecords(refRecord, srvRecord.Target, additionalRecords);

                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, List<DnsResourceRecord> additionalRecords)
        {
            IReadOnlyList<DnsResourceRecord> glueRecords = GetGlueRecordsFrom(refRecord);
            if (glueRecords.Count > 0)
            {
                bool added = false;

                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    if (!glueRecord.IsStale)
                    {
                        added = true;
                        additionalRecords.Add(glueRecord);
                    }
                }

                if (added)
                    return;
            }

            if (_cache.TryGetValue(domain.ToLower(), out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> glueAs = entry.QueryRecords(DnsResourceRecordType.A, true);
                if ((glueAs.Count > 0) && (glueAs[0].Type == DnsResourceRecordType.A))
                    additionalRecords.AddRange(glueAs);

                IReadOnlyList<DnsResourceRecord> glueAAAAs = entry.QueryRecords(DnsResourceRecordType.AAAA, true);
                if ((glueAAAAs.Count > 0) && (glueAAAAs[0].Type == DnsResourceRecordType.AAAA))
                    additionalRecords.AddRange(glueAAAAs);
            }
        }

        #endregion

        #region public

        public virtual DnsDatagram Query(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false)
        {
            if (serveStale)
                throw new NotImplementedException("DnsCache does not implement serve stale.");

            DnsQuestionRecord question = request.Question[0];

            if (_cache.TryGetValue(question.Name.ToLower(), out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> answers = entry.QueryRecords(question.Type, false);
                if (answers.Count > 0)
                {
                    DnsResourceRecord firstRR = answers[0];

                    if (firstRR.RDATA is DnsSpecialCacheRecord dnsSpecialCacheRecord)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, dnsSpecialCacheRecord.RCODE, request.Question, null, dnsSpecialCacheRecord.Authority);

                    DnsResourceRecord lastRR = answers[answers.Count - 1];
                    if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers);

                        ResolveCNAME(question, lastRR, newAnswers);

                        answers = newAnswers;
                    }

                    IReadOnlyList<DnsResourceRecord> additional = null;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                            additional = GetAdditionalRecords(answers);
                            break;
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answers, null, additional);
                }
            }

            if (findClosestNameServers)
            {
                IReadOnlyList<DnsResourceRecord> closestAuthority = GetClosestNameServers(question.Name);
                if (closestAuthority is not null)
                {
                    IReadOnlyList<DnsResourceRecord> additionalRecords = GetAdditionalRecords(closestAuthority);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, closestAuthority, additionalRecords);
                }
            }

            return null;
        }

        public void CacheResponse(DnsDatagram response)
        {
            if (!response.IsResponse || response.Truncation || (response.Question.Count == 0))
                return; //ineligible response

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NxDomain:
                case DnsResponseCode.YXDomain:
                    //cache response after this switch
                    break;

                default:
                    //cache as failure record
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecord(response, true));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record });
                    }

                    return;
            }

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
                                if (response.Authority.Count == 0)
                                {
                                    //add glue from additional section
                                    string nsDomain = (answer.RDATA as DnsNSRecord).NameServer;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (nsDomain.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (additional.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsARecord).Address))
                                                        continue;

                                                    break;

                                                case DnsResourceRecordType.AAAA:
                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsAAAARecord).Address))
                                                        continue;

                                                    break;
                                            }

                                            AddGlueRecordTo(answer, additional);
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                if (response.Authority.Count == 0)
                                {
                                    //add glue from additional section
                                    string mxExchange = (answer.RDATA as DnsMXRecord).Exchange;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (mxExchange.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                            AddGlueRecordTo(answer, additional);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                if (response.Authority.Count == 0)
                                {
                                    //add glue from additional section
                                    string srvTarget = (answer.RDATA as DnsSRVRecord).Target;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (srvTarget.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                            AddGlueRecordTo(answer, additional);
                                    }
                                }
                                break;
                        }
                    }
                    else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        cachableRecords.Add(answer);
                    }
                }
            }

            //get cachable authority records
            if (response.Authority.Count > 0)
            {
                foreach (DnsResourceRecord authority in response.Authority)
                    authority.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                DnsResourceRecord firstAuthority = response.Authority[0];
                if (firstAuthority.Type == DnsResourceRecordType.SOA)
                {
                    if (response.Answer.Count == 0)
                    {
                        //empty response with authority
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, (firstAuthority.RDATA as DnsSOARecord).Minimum, new DnsSpecialCacheRecord(response));
                            record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                            InternalCacheRecords(new DnsResourceRecord[] { record });
                        }
                    }
                    else
                    {
                        //answer response with authority
                        DnsResourceRecord lastAnswer = response.Answer[response.Answer.Count - 1];
                        if (lastAnswer.Type == DnsResourceRecordType.CNAME)
                        {
                            if ((response.RCODE != DnsResponseCode.NxDomain) || (response.Answer.Count == 1))
                            {
                                //negative cache only when RCODE is not NXDOMAIN or when RCODE is NXDOMAIN and there is only 1 CNAME in answer
                                foreach (DnsQuestionRecord question in response.Question)
                                {
                                    DnsResourceRecord record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class, (firstAuthority.RDATA as DnsSOARecord).Minimum, new DnsSpecialCacheRecord(response));
                                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                    InternalCacheRecords(new DnsResourceRecord[] { record });
                                }
                            }
                        }
                    }
                }
                else if (firstAuthority.Type == DnsResourceRecordType.NS)
                {
                    if (response.Answer.Count == 0)
                    {
                        //response is probably referral response
                        bool isReferralResponse = true;

                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            foreach (DnsResourceRecord authority in response.Authority)
                            {
                                if ((authority.Type == DnsResourceRecordType.NS) && (authority.RDATA as DnsNSRecord).NameServer.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                {
                                    //empty response from authority name server that was queried
                                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecord(response));
                                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                    InternalCacheRecords(new DnsResourceRecord[] { record });
                                    isReferralResponse = false;
                                    break;
                                }
                            }
                        }

                        if (isReferralResponse)
                        {
                            //cache and glue suitable NS records
                            foreach (DnsResourceRecord authority in response.Authority)
                            {
                                if (authority.Type != DnsResourceRecordType.NS)
                                    continue;

                                cachableRecords.Add(authority);

                                //add glue from additional section
                                string nsDomain = (authority.RDATA as DnsNSRecord).NameServer;

                                foreach (DnsResourceRecord additional in response.Additional)
                                {
                                    if (nsDomain.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                    {
                                        switch (additional.Type)
                                        {
                                            case DnsResourceRecordType.A:
                                                if (IPAddress.IsLoopback((additional.RDATA as DnsARecord).Address))
                                                    continue;

                                                break;

                                            case DnsResourceRecordType.AAAA:
                                                if (IPAddress.IsLoopback((additional.RDATA as DnsAAAARecord).Address))
                                                    continue;

                                                break;
                                        }

                                        AddGlueRecordTo(authority, additional);
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
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecord(response));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record });
                    }
                }
            }

            if (cachableRecords.Count < 1)
                return; //nothing to cache

            //set expiry for cached records
            foreach (DnsResourceRecord record in cachableRecords)
            {
                record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                foreach (DnsResourceRecord glueRecord in GetGlueRecordsFrom(record))
                    glueRecord.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);
            }

            InternalCacheRecords(cachableRecords);
        }

        public virtual void RemoveExpiredRecords()
        {
            foreach (KeyValuePair<string, DnsCacheEntry> entry in _cache)
            {
                entry.Value.RemoveExpiredRecords();

                if (entry.Value.IsEmpty)
                    _cache.TryRemove(entry.Key, out _); //remove empty entry
            }
        }

        public virtual void Flush()
        {
            _cache.Clear();
        }

        #endregion

        #region properties

        public uint FailureRecordTtl
        {
            get { return _failureRecordTtl; }
            set { _failureRecordTtl = value; }
        }

        public uint NegativeRecordTtl
        {
            get { return _negativeRecordTtl; }
            set { _negativeRecordTtl = value; }
        }

        public uint MinimumRecordTtl
        {
            get { return _minimumRecordTtl; }
            set { _minimumRecordTtl = value; }
        }

        public uint MaximumRecordTtl
        {
            get { return _maximumRecordTtl; }
            set { _maximumRecordTtl = value; }
        }

        public uint ServeStaleTtl
        {
            get { return _serveStaleTtl; }
            set
            {
                if (value > SERVE_STALE_TTL_MAX)
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleTtl), "Serve stale TTL cannot be higher than 7 days. Recommended value is between 1-3 days.");

                _serveStaleTtl = value;
            }
        }

        #endregion

        public class DnsSpecialCacheRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResponseCode _rcode;
            readonly IReadOnlyList<DnsResourceRecord> _authority;
            readonly bool _isFailure;

            #endregion

            #region constructor

            public DnsSpecialCacheRecord(DnsDatagram response, bool isFailure = false)
            {
                _rcode = response.RCODE;
                _authority = response.Authority;
                _isFailure = isFailure;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            {
                throw new InvalidOperationException();
            }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            {
                throw new InvalidOperationException();
            }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                if (obj is DnsSpecialCacheRecord other)
                {
                    if (_rcode != other._rcode)
                        return false;

                    return _authority.Equals(other._authority);
                }

                return false;
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_rcode, _authority);
            }

            public override string ToString()
            {
                string value = _rcode.ToString();

                if (_authority is not null)
                {
                    foreach (DnsResourceRecord record in _authority)
                        value += ", " + record.ToString();
                }

                return value;
            }

            #endregion

            #region properties

            public DnsResponseCode RCODE
            { get { return _rcode; } }

            public IReadOnlyList<DnsResourceRecord> Authority
            { get { return _authority; } }

            public bool IsFailure
            { get { return _isFailure; } }

            public override ushort UncompressedLength
            { get { throw new InvalidOperationException(); } }

            #endregion
        }

        class DnsCacheEntry
        {
            #region variables

            readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

            #endregion

            #region constructor

            public DnsCacheEntry(int capacity)
            {
                _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, capacity);
            }

            #endregion

            #region private

            private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool checkForSpecialCacheRecord)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (record.IsStale)
                        return Array.Empty<DnsResourceRecord>(); //RR Set is stale

                    if (checkForSpecialCacheRecord && (record.RDATA is DnsSpecialCacheRecord))
                        return Array.Empty<DnsResourceRecord>(); //RR Set is special cache record
                }

                if (records.Count > 1)
                {
                    switch (type)
                    {
                        case DnsResourceRecordType.A:
                        case DnsResourceRecordType.AAAA:
                            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records);
                            newRecords.Shuffle(); //shuffle records to allow load balancing
                            return newRecords;
                    }
                }

                return records;
            }

            #endregion

            #region public

            public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
            {
                if ((records.Count > 0) && (records[0].RDATA is DnsSpecialCacheRecord splRecord) && splRecord.IsFailure)
                {
                    //call trying to cache failure record
                    if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    {
                        if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsSpecialCacheRecord existingSplRecord && existingSplRecord.IsFailure) && !DnsResourceRecord.IsRRSetStale(existingRecords))
                            return; //skip to avoid overwriting a useful record with a failure record
                    }
                }

                _entries[type] = records;
            }

            public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool checkForSpecialCacheRecord)
            {
                if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                {
                    IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, checkForSpecialCacheRecord);
                    if (rrset.Count > 0)
                    {
                        if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                            return rrset;
                    }
                }

                if (type == DnsResourceRecordType.ANY)
                {
                    List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                        anyRecords.AddRange(ValidateRRSet(type, entry.Value, true));

                    return anyRecords;
                }

                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    return ValidateRRSet(type, existingRecords, checkForSpecialCacheRecord);

                return Array.Empty<DnsResourceRecord>();
            }

            public void RemoveExpiredRecords()
            {
                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    if (DnsResourceRecord.IsRRSetStale(entry.Value))
                        _entries.TryRemove(entry.Key, out _); //RR Set is expired; remove entry
                }
            }

            #endregion

            #region properties

            public bool IsEmpty
            { get { return _entries.IsEmpty; } }

            #endregion
        }
    }
}
