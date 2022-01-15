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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
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

        protected virtual void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                DnsResourceRecord resourceRecord = resourceRecords[0];

                DnsCacheEntry entry = _cache.GetOrAdd(resourceRecord.Name.ToLower(), delegate (string key)
                {
                    return new DnsCacheEntry(1);
                });

                entry.SetRecords(resourceRecord.Type, resourceRecords);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped entries into cache
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
                {
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
            if (record.Tag is DnsResourceRecordInfo recordInfo)
                return recordInfo.GlueRecords;

            return null;
        }

        protected static IReadOnlyList<DnsResourceRecord> GetRRSIGRecordsFrom(DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo recordInfo)
                return recordInfo.RRSIGRecords;

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

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            //dont return root zone
            return null;
        }

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

            if (recordInfo.RRSIGRecords is null)
                recordInfo.RRSIGRecords = new List<DnsResourceRecord>(1);

            recordInfo.RRSIGRecords.Add(rrsigRecord);
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

        private void InternalCacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                resourceRecord.NormalizeName();

                IReadOnlyList<DnsResourceRecord> glueRecords = GetGlueRecordsFrom(resourceRecord);
                if (glueRecords is not null)
                {
                    foreach (DnsResourceRecord glueRecord in glueRecords)
                        glueRecord.NormalizeName();
                }
            }

            CacheRecords(resourceRecords);
        }

        private IReadOnlyList<DnsResourceRecord> GetClosestNameServers(string domain, bool includeDSRecords)
        {
            domain = domain.ToLower();

            do
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.NS, true);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS))
                    {
                        if (includeDSRecords)
                            return AddDSRecordsTo(entry, records);
                        else
                            return records;
                    }
                }

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            return null;
        }

        private static IReadOnlyList<DnsResourceRecord> AddDSRecordsTo(DnsCacheEntry entry, IReadOnlyList<DnsResourceRecord> nsRecords)
        {
            IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.DS, true);
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

                IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(question.Type, true);
                if (records.Count < 1)
                    break;

                answerRecords.AddRange(records);

                DnsResourceRecord lastRR = records[records.Count - 1];

                if (lastRR.Type != DnsResourceRecordType.CNAME)
                    break;

                lastCNAME = lastRR;
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
            if (glueRecords is not null)
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
                    {
                        if (request.DnssecOk)
                        {
                            bool authenticData;

                            switch (dnsSpecialCacheRecord.Type)
                            {
                                case DnsSpecialCacheRecordType.NegativeCache:
                                    authenticData = true;
                                    break;

                                default:
                                    authenticData = false;
                                    break;
                            }

                            if (request.CheckingDisabled)
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, authenticData, request.CheckingDisabled, dnsSpecialCacheRecord.OriginalRCODE, request.Question, dnsSpecialCacheRecord.OriginalAnswer, dnsSpecialCacheRecord.OriginalAuthority, dnsSpecialCacheRecord.Additional, request.EDNS.UdpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, dnsSpecialCacheRecord.EDnsOptions);
                            else
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, authenticData, request.CheckingDisabled, dnsSpecialCacheRecord.RCODE, request.Question, null, dnsSpecialCacheRecord.Authority, null, request.EDNS.UdpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, dnsSpecialCacheRecord.EDnsOptions);
                        }
                        else
                        {
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, dnsSpecialCacheRecord.RCODE, request.Question, null, dnsSpecialCacheRecord.NoDnssecAuthority, null, request.EDNS is null ? ushort.MinValue : request.EDNS.UdpPayloadSize, EDnsHeaderFlags.None, dnsSpecialCacheRecord.EDnsOptions);
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

                    if (request.DnssecOk)
                    {
                        //DNSSEC enabled; insert RRSIG records
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers.Count * 2);
                        List<DnsResourceRecord> newAuthority = null;

                        foreach (DnsResourceRecord answer in answers)
                        {
                            newAnswers.Add(answer);

                            IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRRSIGRecordsFrom(answer);
                            if (rrsigRecords is not null)
                            {
                                newAnswers.AddRange(rrsigRecords);

                                foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                                {
                                    if (!DnsRRSIGRecord.IsWildcard(rrsigRecord))
                                        continue;

                                    //add NSEC/NSEC3 for the wildcard proof
                                    if (newAuthority is null)
                                        newAuthority = new List<DnsResourceRecord>(2);

                                    IReadOnlyList<DnsResourceRecord> nsecRecords = GetNSECRecordsFrom(answer);
                                    if (nsecRecords is not null)
                                    {
                                        foreach (DnsResourceRecord nsecRecord in nsecRecords)
                                        {
                                            newAuthority.Add(nsecRecord);

                                            IReadOnlyList<DnsResourceRecord> nsecRRSIGRecords = GetRRSIGRecordsFrom(nsecRecord);
                                            if (nsecRRSIGRecords is not null)
                                                newAuthority.AddRange(nsecRRSIGRecords);
                                        }
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

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, answers[0].DnssecStatus == DnssecStatus.Secure, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answers, authority, additional);
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

                IReadOnlyList<DnsResourceRecord> closestAuthority = GetClosestNameServers(domain, request.DnssecOk);
                if (closestAuthority is not null)
                {
                    IReadOnlyList<DnsResourceRecord> additionalRecords = GetAdditionalRecords(closestAuthority);

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, closestAuthority[0].DnssecStatus == DnssecStatus.Secure, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, closestAuthority, additionalRecords);
                }
            }

            return null;
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false)
        {
            if (!response.IsResponse || response.Truncation || (response.Question.Count == 0))
                return; //ineligible response

            //set expiry for all records
            {
                foreach (DnsResourceRecord record in response.Answer)
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                foreach (DnsResourceRecord record in response.Authority)
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                foreach (DnsResourceRecord record in response.Additional)
                {
                    if (record.Type == DnsResourceRecordType.OPT)
                        continue;

                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);
                }
            }

            if (isDnssecBadCache)
            {
                //cache as bad cache record with failure TTL
                foreach (DnsQuestionRecord question in response.Question)
                {
                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.BadCache, response));
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                    InternalCacheRecords(new DnsResourceRecord[] { record });
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

                        InternalCacheRecords(new DnsResourceRecord[] { record });
                    }

                    return;
            }

            //attach RRSIG to records
            {
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

                foreach (DnsResourceRecord rrsigRecord in response.Additional)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecord rrsig = rrsigRecord.RDATA as DnsRRSIGRecord;

                    foreach (DnsResourceRecord record in response.Additional)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                            AddRRSIGRecordTo(record, rrsigRecord);
                    }
                }
            }

            //combine all records in the response
            List<DnsResourceRecord> cachableRecords = new List<DnsResourceRecord>(response.Answer.Count);

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
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

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
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

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
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

                                        if (srvTarget.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                            AddGlueRecordTo(answer, additional);
                                    }
                                }
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

            //get cachable authority records
            if (response.Authority.Count > 0)
            {
                DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
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

                                InternalCacheRecords(new DnsResourceRecord[] { record });
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

                                        InternalCacheRecords(new DnsResourceRecord[] { record });
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
                                        //empty response from authority name server that was queried; dont cache authority section with NS records
                                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecord(DnsSpecialCacheRecordType.NegativeCache, response.RCODE, Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>(), response.EDNS, response.DnsClientExtendedErrors));
                                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl);

                                        InternalCacheRecords(new DnsResourceRecord[] { record });
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
                                            break;

                                        case DnsResourceRecordType.DS:
                                            cachableRecords.Add(authority);
                                            break;

                                        case DnsResourceRecordType.NSEC:
                                        case DnsResourceRecordType.NSEC3:
                                            foreach (DnsResourceRecord record in response.Authority)
                                            {
                                                if (record.Type == DnsResourceRecordType.NS)
                                                {
                                                    AddNSECRecordTo(record, authority);
                                                    break;
                                                }
                                            }
                                            break;
                                    }
                                }
                            }
                        }

                        break;
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

                        InternalCacheRecords(new DnsResourceRecord[] { record });
                    }
                }
            }

            if (cachableRecords.Count > 0)
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

            readonly IReadOnlyList<EDnsOption> _ednsOptions;
            readonly IReadOnlyList<DnsResourceRecord> _noDnssecAuthority;

            #endregion

            #region constructor

            public DnsSpecialCacheRecord(DnsSpecialCacheRecordType type, DnsDatagram response)
                : this(type, response.RCODE, response.Answer, response.Authority, response.Additional, response.EDNS, response.DnsClientExtendedErrors)
            { }

            public DnsSpecialCacheRecord(DnsSpecialCacheRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority, IReadOnlyList<DnsResourceRecord> additional, DnsDatagramEdns edns, IReadOnlyList<EDnsExtendedDnsErrorOption> dnsClientExtendedErrors)
            {
                _type = type;
                _rcode = rcode;
                _answer = answer;
                _authority = authority;
                _additional = additional;

                //prepare EDNS options
                {
                    List<EDnsOption> ednsOptions = new List<EDnsOption>();

                    //copy extended dns errors from response
                    if (edns is not null)
                    {
                        foreach (EDnsOption option in edns.Options)
                        {
                            if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                ednsOptions.Add(option);
                        }
                    }

                    //copy extended dns errors generated by dns client
                    foreach (EDnsExtendedDnsErrorOption dnsError in dnsClientExtendedErrors)
                        ednsOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, dnsError));

                    //add additional extended dns error
                    switch (rcode)
                    {
                        case DnsResponseCode.NoError:
                        case DnsResponseCode.NxDomain:
                        case DnsResponseCode.YXDomain:
                            break;

                        default:
                            ednsOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOption(EDnsExtendedDnsErrorCode.CachedError, null)));
                            break;
                    }

                    _ednsOptions = ednsOptions;
                }

                //get authority section with no dnssec records
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
                        List<DnsResourceRecord> noDnssecAuthority = new List<DnsResourceRecord>();

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
                                    noDnssecAuthority.Add(record);
                                    break;
                            }
                        }

                        _noDnssecAuthority = noDnssecAuthority;
                    }
                    else
                    {
                        _noDnssecAuthority = _authority;
                    }
                }

                //remove OPT additional
                if ((_additional.Count == 1) && (_additional[0].Type == DnsResourceRecordType.OPT))
                {
                    _additional = Array.Empty<DnsResourceRecord>();
                }
                else if (_additional.Count > 0)
                {
                    bool foundOpt = false;

                    foreach (DnsResourceRecord record in _additional)
                    {
                        if (record.Type == DnsResourceRecordType.OPT)
                        {
                            foundOpt = true;
                            break;
                        }
                    }

                    if (foundOpt)
                    {
                        List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(_additional.Count - 1);

                        foreach (DnsResourceRecord record2 in _additional)
                        {
                            if (record2.Type == DnsResourceRecordType.OPT)
                                continue;

                            newAdditional.Add(record2);
                        }

                        _additional = newAdditional;
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
                string value = _type.ToString() + ": " + _rcode.ToString();

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

            public IReadOnlyList<DnsResourceRecord> OriginalAuthority
            { get { return _authority; } }

            public IReadOnlyList<DnsResourceRecord> Authority
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return Array.Empty<DnsResourceRecord>();

                    return _authority;
                }
            }

            public IReadOnlyList<DnsResourceRecord> NoDnssecAuthority
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return Array.Empty<DnsResourceRecord>();

                    return _noDnssecAuthority;
                }
            }

            public IReadOnlyList<DnsResourceRecord> Additional
            { get { return _additional; } }

            public IReadOnlyList<EDnsOption> EDnsOptions
            { get { return _ednsOptions; } }

            public override ushort UncompressedLength
            { get { throw new InvalidOperationException(); } }

            #endregion
        }

        class DnsCacheEntry
        {
            #region variables

            ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

            #endregion

            #region constructor

            public DnsCacheEntry(int capacity)
            {
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

            public void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
            {
                if ((records.Count > 0) && (records[0].RDATA is DnsSpecialCacheRecord splRecord) && (splRecord.Type == DnsSpecialCacheRecordType.FailureCache))
                {
                    //call trying to cache failure record
                    if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                    {
                        if ((existingRecords.Count > 0) && !(existingRecords[0].RDATA is DnsSpecialCacheRecord existingSplRecord && (existingSplRecord.Type == DnsSpecialCacheRecordType.FailureCache)) && !DnsResourceRecord.IsRRSetStale(existingRecords))
                            return; //skip to avoid overwriting a useful record with a failure record
                    }
                }

                _entries[type] = records;
            }

            public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool skipSpecialCacheRecord)
            {
                switch (type)
                {
                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.DS:
                    case DnsResourceRecordType.DNSKEY:
                        {
                            //since some zones have CNAME at apex!
                            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                                return ValidateRRSet(type, existingRecords, skipSpecialCacheRecord);

                            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                            {
                                IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, skipSpecialCacheRecord);
                                if (rrset.Count > 0)
                                {
                                    if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                                        return rrset;
                                }
                            }
                        }
                        break;

                    case DnsResourceRecordType.ANY:
                        List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                        foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                            anyRecords.AddRange(ValidateRRSet(type, entry.Value, true));

                        return anyRecords;

                    default:
                        {
                            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                            {
                                IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(type, existingCNAMERecords, skipSpecialCacheRecord);
                                if (rrset.Count > 0)
                                {
                                    if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecord))
                                        return rrset;
                                }
                            }

                            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                                return ValidateRRSet(type, existingRecords, skipSpecialCacheRecord);
                        }
                        break;
                }

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

        class DnsResourceRecordInfo
        {
            public List<DnsResourceRecord> GlueRecords { get; set; }

            public List<DnsResourceRecord> RRSIGRecords { get; set; }

            public List<DnsResourceRecord> NSECRecords { get; set; }
        }
    }
}
