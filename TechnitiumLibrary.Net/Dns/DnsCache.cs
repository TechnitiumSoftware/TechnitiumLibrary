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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    //Negative Caching of DNS Queries (DNS NCACHE) 
    //https://datatracker.ietf.org/doc/html/rfc2308

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

        protected virtual void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords, bool parentSide)
        {
            if (resourceRecords.Count == 1)
            {
                DnsCacheEntry entry = _cache.GetOrAdd(resourceRecords[0].Name.ToLower(), delegate (string key)
                {
                    return new DnsCacheEntry(1, parentSide);
                });

                entry.SetRecords(resourceRecords[0].Type, resourceRecords, parentSide);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped entries into cache
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
                {
                    DnsCacheEntry entry = _cache.GetOrAdd(cacheEntry.Key.ToLower(), delegate (string key)
                    {
                        return new DnsCacheEntry(cacheEntry.Value.Count, parentSide);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                        entry.SetRecords(cacheTypeEntry.Key, cacheTypeEntry.Value, parentSide);
                }
            }
        }

        protected static IReadOnlyList<DnsResourceRecord> GetGlueRecordsFrom(DnsResourceRecord record)
        {
            if ((record.Tag is DnsResourceRecordInfo recordInfo) && (recordInfo.GlueRecords is not null))
                return recordInfo.GlueRecords;

            return Array.Empty<DnsResourceRecord>();
        }

        protected static DnsResourceRecord GetRRSIGRecordFrom(DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo recordInfo)
                return recordInfo.RRSIGRecord;

            return null;
        }

        protected static IReadOnlyList<DnsResourceRecord> GetNSECRecordsFrom(DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo recordInfo)
                return recordInfo.NSECRecords;

            return null;
        }

        #endregion

        #region private

        private static void AddGlueRecordTo(DnsResourceRecord record, DnsResourceRecord glueRecord)
        {
            if (record.Tag is not DnsResourceRecordInfo recordInfo)
            {
                recordInfo = new DnsResourceRecordInfo();
                record.Tag = recordInfo;
            }

            if (recordInfo.GlueRecords is null)
                recordInfo.GlueRecords = new List<DnsResourceRecord>(2);

            recordInfo.GlueRecords.Add(glueRecord);
        }

        private static void AddRRSIGRecordTo(DnsResourceRecord record, DnsResourceRecord rrsigRecord)
        {
            if (record.Tag is not DnsResourceRecordInfo recordInfo)
            {
                recordInfo = new DnsResourceRecordInfo();
                record.Tag = recordInfo;
            }

            recordInfo.RRSIGRecord = rrsigRecord;
        }

        private static void AddNSECRecordTo(DnsResourceRecord record, DnsResourceRecord nsecRecord)
        {
            if (record.Tag is not DnsResourceRecordInfo recordInfo)
            {
                recordInfo = new DnsResourceRecordInfo();
                record.Tag = recordInfo;
            }

            if (recordInfo.NSECRecords is null)
                recordInfo.NSECRecords = new List<DnsResourceRecord>(2);

            recordInfo.NSECRecords.Add(nsecRecord);
        }

        private void InternalCacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords, bool parentSide)
        {
            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                resourceRecord.NormalizeName();

                foreach (DnsResourceRecord glueRecord in GetGlueRecordsFrom(resourceRecord))
                    glueRecord.NormalizeName();
            }

            CacheRecords(resourceRecords, parentSide);
        }

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

        private IReadOnlyList<DnsResourceRecord> GetClosestNameServers(string domain, bool includeDSRecords)
        {
            domain = domain.ToLower();

            do
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    {
                        IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.NS, true, false);
                        if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS))
                        {
                            if (includeDSRecords)
                                return AddDSRecordsTo(entry, records);
                            else
                                return records;
                        }
                    }

                    {
                        IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.NS, true, true);
                        if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS))
                        {
                            if (includeDSRecords)
                                return AddDSRecordsTo(entry, records);
                            else
                                return records;
                        }
                    }
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            return null;
        }

        private static IReadOnlyList<DnsResourceRecord> AddDSRecordsTo(DnsCacheEntry entry, IReadOnlyList<DnsResourceRecord> nsRecords)
        {
            IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.DS, true, true);
            if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.DS))
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + records.Count);

                newNSRecords.AddRange(nsRecords);
                newNSRecords.AddRange(records);

                return newNSRecords;
            }

            //no DS records found check for NSEC records
            IReadOnlyList<DnsResourceRecord> nsecRecords = GetNSECRecordsFrom(nsRecords[0]);
            if (nsecRecords is not null)
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + nsecRecords.Count);

                newNSRecords.AddRange(nsRecords);
                newNSRecords.AddRange(nsecRecords);

                return newNSRecords;
            }

            //found nothing; return original NS records
            return nsRecords;
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                if (!_cache.TryGetValue((lastCNAME.RDATA as DnsCNAMERecord).Domain.ToLower(), out DnsCacheEntry entry))
                    break;

                IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(question.Type, true, false);
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
                IReadOnlyList<DnsResourceRecord> glueAs = entry.QueryRecords(DnsResourceRecordType.A, true, false);
                if ((glueAs.Count > 0) && (glueAs[0].Type == DnsResourceRecordType.A))
                    additionalRecords.AddRange(glueAs);

                IReadOnlyList<DnsResourceRecord> glueAAAAs = entry.QueryRecords(DnsResourceRecordType.AAAA, true, false);
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

            bool dnssecOk;
            ushort udpPayloadSize;
            EDnsHeaderFlags ednsFlags;

            if (request.EDNS is null)
            {
                dnssecOk = false;
                udpPayloadSize = ushort.MinValue;
                ednsFlags = EDnsHeaderFlags.None;
            }
            else
            {
                dnssecOk = request.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK);
                udpPayloadSize = request.EDNS.UdpPayloadSize;
                ednsFlags = request.EDNS.Flags;
            }

            DnsQuestionRecord question = request.Question[0];

            if (_cache.TryGetValue(question.Name.ToLower(), out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> answers = entry.QueryRecords(question.Type, false, question.Type == DnsResourceRecordType.DS);
                if (answers.Count > 0)
                {
                    DnsResourceRecord firstRR = answers[0];

                    if (firstRR.RDATA is DnsSpecialCacheRecord dnsSpecialCacheRecord)
                    {
                        if (dnssecOk)
                        {
                            if (request.CheckingDisabled)
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, dnsSpecialCacheRecord.OriginalRCODE, request.Question, dnsSpecialCacheRecord.OriginalAnswer, dnsSpecialCacheRecord.OriginalAuthority, dnsSpecialCacheRecord.OriginalAdditional, udpPayloadSize, ednsFlags);
                            else
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, dnsSpecialCacheRecord.RCODE, request.Question, null, dnsSpecialCacheRecord.Authority, null, udpPayloadSize, ednsFlags);
                        }
                        else
                        {
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, dnsSpecialCacheRecord.RCODE, request.Question, null, dnsSpecialCacheRecord.NonDnssecAuthority, null, udpPayloadSize, ednsFlags);
                        }
                    }

                    DnsResourceRecord lastRR = answers[answers.Count - 1];
                    if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers.Count + 3);

                        newAnswers.AddRange(answers);

                        ResolveCNAME(question, lastRR, newAnswers);

                        answers = newAnswers;
                    }

                    IReadOnlyList<DnsResourceRecord> authority = null;

                    if (dnssecOk)
                    {
                        //DNSSEC enabled; insert RRSIG records
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers.Count * 2);
                        List<DnsResourceRecord> newAuthority = null;

                        foreach (DnsResourceRecord answer in answers)
                        {
                            newAnswers.Add(answer);

                            DnsResourceRecord rrsigRecord = GetRRSIGRecordFrom(answer);
                            if (rrsigRecord is not null)
                            {
                                newAnswers.Add(rrsigRecord);

                                if (DnsRRSIGRecord.IsWildcard(rrsigRecord))
                                {
                                    //add NSEC/NSEC3 for the wildcard proof
                                    if (newAuthority is null)
                                        newAuthority = new List<DnsResourceRecord>(2);

                                    IReadOnlyList<DnsResourceRecord> nsecRecords = GetNSECRecordsFrom(answer);

                                    foreach (DnsResourceRecord nsecRecord in nsecRecords)
                                    {
                                        newAuthority.Add(nsecRecord);

                                        DnsResourceRecord nsecRRSIGRecord = GetRRSIGRecordFrom(nsecRecord);
                                        if (nsecRRSIGRecord is not null)
                                            newAuthority.Add(nsecRRSIGRecord);
                                    }
                                }
                            }
                        }

                        answers = newAnswers;
                        authority = newAuthority;
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

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, answers[0].DnssecStatus == DnssecStatus.Secure, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answers, authority, additional, udpPayloadSize, ednsFlags);
                }
            }

            if (findClosestNameServers)
            {
                string domain;

                if (question.Type == DnsResourceRecordType.DS)
                {
                    //find parent zone NS
                    domain = GetParentZone(question.Name);
                    if (domain is null)
                        return null; //dont find NS for root
                }
                else
                {
                    domain = question.Name;
                }

                IReadOnlyList<DnsResourceRecord> closestAuthority = GetClosestNameServers(domain, dnssecOk);
                if (closestAuthority is not null)
                {
                    IReadOnlyList<DnsResourceRecord> additionalRecords = GetAdditionalRecords(closestAuthority);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, closestAuthority[0].DnssecStatus == DnssecStatus.Secure, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, closestAuthority, additionalRecords, udpPayloadSize, ednsFlags);
                }
            }

            return null;
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false)
        {
            if (!response.IsResponse || response.Truncation || (response.Question.Count == 0))
                return; //ineligible response

            if (isDnssecBadCache)
            {
                //cache as bad cache record with failure TTL
                foreach (DnsQuestionRecord question in response.Question)
                {
                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.BadCache, response));
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                    InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                }

                return;
            }

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
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.FailureCache, response));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                    }

                    return;
            }

            //combine all records in the response
            List<DnsResourceRecord> parentSideCachableRecords = new List<DnsResourceRecord>(response.Authority.Count);
            List<DnsResourceRecord> cachableRecords = new List<DnsResourceRecord>(response.Answer.Count);
            bool dnssecOk = (response.EDNS is not null) && response.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK);

            //get cachable answer records
            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                cachableRecords.Add(answer);

                                qName = (answer.RDATA as DnsCNAMERecord).Domain;
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    string nsDomain = (answer.RDATA as DnsNSRecord).NameServer;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (dnssecOk && (additional.DnssecStatus != DnssecStatus.Secure) && (additional.DnssecStatus != DnssecStatus.Insecure))
                                            continue;

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
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    string mxExchange = (answer.RDATA as DnsMXRecord).Exchange;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (dnssecOk && (additional.DnssecStatus != DnssecStatus.Secure) && (additional.DnssecStatus != DnssecStatus.Insecure))
                                            continue;

                                        if (mxExchange.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                            AddGlueRecordTo(answer, additional);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    string srvTarget = (answer.RDATA as DnsSRVRecord).Target;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        if (dnssecOk && (additional.DnssecStatus != DnssecStatus.Secure) && (additional.DnssecStatus != DnssecStatus.Insecure))
                                            continue;

                                        if (srvTarget.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                            AddGlueRecordTo(answer, additional);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.DS:
                                parentSideCachableRecords.Add(answer);
                                break;

                            case DnsResourceRecordType.RRSIG:
                                if (question.Type == DnsResourceRecordType.RRSIG)
                                    cachableRecords.Add(answer);

                                break;

                            default:
                                cachableRecords.Add(answer);
                                break;
                        }
                    }
                    else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        cachableRecords.Add(answer);
                    }
                }
            }

            if (dnssecOk)
            {
                //attach RRSIG to records
                foreach (DnsResourceRecord rrsigRecord in response.Answer)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecord rrsig = rrsigRecord.RDATA as DnsRRSIGRecord;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            AddRRSIGRecordTo(record, rrsigRecord);

                            if (DnsRRSIGRecord.IsWildcard(rrsigRecord))
                            {
                                //record is wildcard synthesized
                                //add NSEC from authority if any

                                foreach (DnsResourceRecord authority in response.Authority)
                                {
                                    switch (authority.Type)
                                    {
                                        case DnsResourceRecordType.NSEC:
                                        case DnsResourceRecordType.NSEC3:
                                            AddNSECRecordTo(record, authority);
                                            break;
                                    }
                                }
                            }

                            break;
                        }
                    }
                }

                foreach (DnsResourceRecord rrsigRecord in response.Authority)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecord rrsig = rrsigRecord.RDATA as DnsRRSIGRecord;

                    foreach (DnsResourceRecord record in response.Authority)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                            AddRRSIGRecordTo(record, rrsigRecord);
                    }
                }
            }

            //get cachable authority records
            if (response.Authority.Count > 0)
            {
                DnsResourceRecord firstAuthority = null;

                foreach (DnsResourceRecord authority in response.Authority)
                {
                    authority.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                    if (firstAuthority is null)
                    {
                        switch (authority.Type)
                        {
                            case DnsResourceRecordType.SOA:
                            case DnsResourceRecordType.NS:
                                firstAuthority = authority;
                                break;
                        }
                    }
                }

                if (firstAuthority is not null)
                {
                    switch (firstAuthority.Type)
                    {
                        case DnsResourceRecordType.SOA:
                            if (response.Answer.Count == 0)
                            {
                                //empty response with authority
                                foreach (DnsQuestionRecord question in response.Question)
                                {
                                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, (firstAuthority.RDATA as DnsSOARecord).Minimum, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.NegativeCache, response));
                                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                    InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                                }
                            }
                            else
                            {
                                //answer response with authority
                                DnsResourceRecord lastAnswer = response.GetLastAnswerRecord();
                                if (lastAnswer.Type == DnsResourceRecordType.CNAME)
                                {
                                    if ((response.RCODE != DnsResponseCode.NxDomain) || (response.Answer.Count == 1))
                                    {
                                        //negative cache only when RCODE is not NXDOMAIN or when RCODE is NXDOMAIN and there is only 1 CNAME in answer
                                        foreach (DnsQuestionRecord question in response.Question)
                                        {
                                            DnsResourceRecord record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class, (firstAuthority.RDATA as DnsSOARecord).Minimum, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.NegativeCache, response));
                                            record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                            InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                                        }
                                    }
                                }
                            }

                            break;

                        case DnsResourceRecordType.NS:
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
                                            DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.NegativeCache, response));
                                            record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                            InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                                            isReferralResponse = false;
                                            break;
                                        }
                                    }
                                }

                                if (isReferralResponse)
                                {
                                    //cache and glue suitable NS & DS records
                                    foreach (DnsResourceRecord authority in response.Authority)
                                    {
                                        switch (authority.Type)
                                        {
                                            case DnsResourceRecordType.NS:
                                                parentSideCachableRecords.Add(authority);

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
                                                break;

                                            case DnsResourceRecordType.DS:
                                                if (dnssecOk)
                                                    parentSideCachableRecords.Add(authority);

                                                break;

                                            case DnsResourceRecordType.NSEC:
                                            case DnsResourceRecordType.NSEC3:
                                                if (dnssecOk)
                                                {
                                                    foreach (DnsResourceRecord record in response.Authority)
                                                    {
                                                        if (record.Type == DnsResourceRecordType.NS)
                                                        {
                                                            AddNSECRecordTo(record, authority);
                                                            break;
                                                        }
                                                    }
                                                }

                                                break;
                                        }
                                    }
                                }
                            }

                            break;

                        default:
                            throw new InvalidOperationException();
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
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.NegativeCache, response));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record }, question.Type == DnsResourceRecordType.DS);
                    }
                }
            }

            if (parentSideCachableRecords.Count > 0)
            {
                foreach (DnsResourceRecord record in parentSideCachableRecords)
                {
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                    foreach (DnsResourceRecord glueRecord in GetGlueRecordsFrom(record))
                        glueRecord.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);
                }

                InternalCacheRecords(parentSideCachableRecords, true);
            }

            if (cachableRecords.Count > 0)
            {
                //set expiry for cached records
                foreach (DnsResourceRecord record in cachableRecords)
                {
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                    foreach (DnsResourceRecord glueRecord in GetGlueRecordsFrom(record))
                        glueRecord.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);
                }

                InternalCacheRecords(cachableRecords, false);
            }
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

        public enum DnsSpecialCacheRecordType
        {
            Unknown = 0,
            NegativeCache = 1,
            FailureCache = 2,
            BadCache = 3
        }

        public class DnsSpecialCacheRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsSpecialCacheRecordType _type;
            readonly DnsResponseCode _rcode;
            readonly IReadOnlyList<DnsResourceRecord> _answer;
            readonly IReadOnlyList<DnsResourceRecord> _authority;
            readonly IReadOnlyList<DnsResourceRecord> _additional;
            readonly IReadOnlyList<DnsResourceRecord> _nonDnssecAuthority;

            #endregion

            #region constructor

            public DnsSpecialCacheRecord(DnsSpecialCacheRecordType type, DnsDatagram response)
                : this(type, response.RCODE, response.Answer, response.Authority, response.Additional)
            { }

            public DnsSpecialCacheRecord(DnsSpecialCacheRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority, IReadOnlyList<DnsResourceRecord> additional)
            {
                _type = type;
                _rcode = rcode;
                _answer = answer;
                _authority = authority;
                _additional = additional;

                {
                    bool foundDnssecRecords = false;

                    foreach (DnsResourceRecord record in _authority)
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.DS:
                            case DnsResourceRecordType.DNSKEY:
                            case DnsResourceRecordType.RRSIG:
                            case DnsResourceRecordType.NSEC:
                            case DnsResourceRecordType.NSEC3:
                                foundDnssecRecords = true;
                                break;
                        }

                        if (foundDnssecRecords)
                            break;
                    }

                    if (foundDnssecRecords)
                    {
                        List<DnsResourceRecord> nonDnssecAuthority = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord record in _authority)
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.DS:
                                case DnsResourceRecordType.DNSKEY:
                                case DnsResourceRecordType.RRSIG:
                                case DnsResourceRecordType.NSEC:
                                case DnsResourceRecordType.NSEC3:
                                    break;

                                default:
                                    nonDnssecAuthority.Add(record);
                                    break;
                            }
                        }

                        _nonDnssecAuthority = nonDnssecAuthority;
                    }
                    else
                    {
                        _nonDnssecAuthority = _authority;
                    }
                }

                if ((_additional.Count == 1) && (_additional[0].Type == DnsResourceRecordType.OPT))
                {
                    _additional = Array.Empty<DnsResourceRecord>();
                }
                else if (_additional.Count > 0)
                {
                    foreach (DnsResourceRecord record in _additional)
                    {
                        if (record.Type == DnsResourceRecordType.OPT)
                        {
                            //found opt in additional; remove it
                            List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(_additional.Count - 1);

                            foreach (DnsResourceRecord record2 in _additional)
                            {
                                if (record2.Type == DnsResourceRecordType.OPT)
                                    continue;

                                newAdditional.Add(record2);
                            }

                            _additional = newAdditional;
                            break;
                        }
                    }
                }
            }

            #endregion

            #region protected

            protected override void ReadRecordData(Stream s)
            {
                throw new InvalidOperationException();
            }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
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
                    if (_type != other._type)
                        return false;

                    if (_rcode != other._rcode)
                        return false;

                    if (!_answer.Equals(other._answer))
                        return false;

                    if (!_authority.Equals(other._authority))
                        return false;

                    if (!_additional.Equals(other._additional))
                        return false;

                    return true;
                }

                return false;
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_type, _rcode, _answer, _authority, _additional);
            }

            public override string ToString()
            {
                string value = _type.ToString() + " " + _rcode.ToString();

                if (_authority is not null)
                {
                    foreach (DnsResourceRecord record in _authority)
                        value += ", " + record.ToString();
                }

                return value;
            }

            #endregion

            #region properties

            public DnsSpecialCacheRecordType Type
            { get { return _type; } }

            public DnsResponseCode RCODE
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return DnsResponseCode.ServerFailure;

                    return _rcode;
                }
            }

            public DnsResponseCode OriginalRCODE
            { get { return _rcode; } }

            public IReadOnlyList<DnsResourceRecord> OriginalAnswer
            { get { return _answer; } }

            public IReadOnlyList<DnsResourceRecord> Authority
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return Array.Empty<DnsResourceRecord>();

                    return _authority;
                }
            }

            public IReadOnlyList<DnsResourceRecord> OriginalAuthority
            { get { return _authority; } }

            public IReadOnlyList<DnsResourceRecord> NonDnssecAuthority
            { get { return _nonDnssecAuthority; } }

            public IReadOnlyList<DnsResourceRecord> OriginalAdditional
            { get { return _additional; } }

            public override ushort UncompressedLength
            { get { throw new InvalidOperationException(); } }

            #endregion
        }

        class DnsCacheEntry
        {
            #region variables

            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _parentSideEntries;
            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

            #endregion

            #region constructor

            public DnsCacheEntry(int capacity, bool parentSide)
            {
                if (parentSide)
                    _parentSideEntries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, capacity);
                else
                    _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, capacity);
            }

            #endregion

            #region private

            private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool skipSpecialCacheRecord)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (record.IsStale)
                        return Array.Empty<DnsResourceRecord>(); //RR Set is stale

                    if (skipSpecialCacheRecord && (record.RDATA is DnsSpecialCacheRecord))
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

            public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, bool parentSide)
            {
                ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries;

                if (parentSide)
                {
                    if (_parentSideEntries is null)
                        _parentSideEntries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, 1);

                    entries = _parentSideEntries;
                }
                else
                {
                    if (_entries is null)
                        _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, 1);

                    entries = _entries;
                }

                if ((records.Count > 0) && (records[0].RDATA is DnsSpecialCacheRecord splRecord) && (splRecord.Type == DnsSpecialCacheRecordType.FailureCache))
                {
                    //call trying to cache failure record
                    if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    {
                        if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsSpecialCacheRecord existingSplRecord && (existingSplRecord.Type == DnsSpecialCacheRecordType.FailureCache)) && !DnsResourceRecord.IsRRSetStale(existingRecords))
                            return; //skip to avoid overwriting a useful record with a failure record
                    }
                }

                entries[type] = records;
            }

            public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool skipSpecialCacheRecord, bool parentSide)
            {
                ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries;

                if (parentSide)
                    entries = _parentSideEntries;
                else
                    entries = _entries;

                if (entries is null)
                    return Array.Empty<DnsResourceRecord>();

                if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                {
                    IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, skipSpecialCacheRecord);
                    if (rrset.Count > 0)
                    {
                        if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                            return rrset;
                    }
                }

                if (type == DnsResourceRecordType.ANY)
                {
                    List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in entries)
                        anyRecords.AddRange(ValidateRRSet(type, entry.Value, true));

                    return anyRecords;
                }

                if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    return ValidateRRSet(type, existingRecords, skipSpecialCacheRecord);

                return Array.Empty<DnsResourceRecord>();
            }

            public void RemoveExpiredRecords()
            {
                if (_parentSideEntries is not null)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _parentSideEntries)
                    {
                        if (DnsResourceRecord.IsRRSetStale(entry.Value))
                            _parentSideEntries.TryRemove(entry.Key, out _); //RR Set is expired; remove entry
                    }
                }

                if (_entries is not null)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                    {
                        if (DnsResourceRecord.IsRRSetStale(entry.Value))
                            _entries.TryRemove(entry.Key, out _); //RR Set is expired; remove entry
                    }
                }
            }

            #endregion

            #region properties

            public bool IsEmpty
            { get { return ((_parentSideEntries is null) || _parentSideEntries.IsEmpty) && ((_entries is null) || _entries.IsEmpty); } }

            #endregion
        }

        class DnsResourceRecordInfo
        {
            public List<DnsResourceRecord> GlueRecords { get; set; }

            public DnsResourceRecord RRSIGRecord { get; set; }

            public List<DnsResourceRecord> NSECRecords { get; set; }
        }
    }
}
