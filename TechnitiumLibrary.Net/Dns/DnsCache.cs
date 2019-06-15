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
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public abstract class DnsCache
    {
        #region variables

        readonly uint _negativeRecordTtl;
        readonly uint _minimumRecordTtl;
        readonly uint _serveStaleTtl;

        #endregion

        #region constructor

        public DnsCache(uint negativeRecordTtl, uint minimumRecordTtl, uint serveStaleTtl)
        {
            _negativeRecordTtl = negativeRecordTtl;
            _minimumRecordTtl = minimumRecordTtl;
            _serveStaleTtl = serveStaleTtl;
        }

        #endregion

        #region protected

        protected abstract void CacheRecords(ICollection<DnsResourceRecord> resourceRecords);

        #endregion

        #region public

        public abstract DnsDatagram Query(DnsDatagram request);

        public void CacheResponse(DnsDatagram response)
        {
            if (!response.Header.IsResponse || response.Header.Truncation || (response.Question.Length == 0))
                return; //ineligible response

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NameError:
                    //cache response after this switch
                    break;

                default:
                    //cache as failure record with RCODE
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsFailureRecord(response.Header.RCODE));
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
                                qName = (answer.RDATA as DnsCNAMERecord).CNAMEDomainName;
                                break;

                            case DnsResourceRecordType.NS:
                                string nsDomain = (answer.RDATA as DnsNSRecord).NSDomainName;

                                if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (DnsResourceRecord record in response.Additional)
                                    {
                                        if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                            cachableRecords.Add(record);
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
            if (response.Authority.Length > 0)
            {
                DnsResourceRecord authority = response.Authority[0];
                if (authority.Type == DnsResourceRecordType.SOA)
                {
                    authority.SetExpiry(_minimumRecordTtl, _serveStaleTtl);

                    if (response.Answer.Length == 0)
                    {
                        //empty response with authority
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase) || authority.Name.Equals("", StringComparison.OrdinalIgnoreCase))
                            {
                                DnsResourceRecord record = null;

                                switch (response.Header.RCODE)
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
                        DnsResourceRecord lastAnswer = response.Answer[response.Answer.Length - 1];
                        if (lastAnswer.Type == DnsResourceRecordType.CNAME)
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase))
                                {
                                    DnsResourceRecord record = null;

                                    switch (response.Header.RCODE)
                                    {
                                        case DnsResponseCode.NameError:
                                            record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).CNAMEDomainName, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsNXRecord(authority));
                                            break;

                                        case DnsResponseCode.NoError:
                                            record = new DnsResourceRecord((lastAnswer.RDATA as DnsCNAMERecord).CNAMEDomainName, question.Type, question.Class, (authority.RDATA as DnsSOARecord).Minimum, new DnsEmptyRecord(authority));
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
                    if (response.Answer.Length == 0)
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            foreach (DnsResourceRecord authorityRecord in response.Authority)
                            {
                                if ((authorityRecord.Type == DnsResourceRecordType.NS) && (authorityRecord.RDATA as DnsNSRecord).NSDomainName.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                {
                                    //empty response from authority name server that was queried
                                    DnsResourceRecord record = null;

                                    switch (response.Header.RCODE)
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
                    if ((response.Question[0].Type != DnsResourceRecordType.NS) || (response.Answer.Length == 0))
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            foreach (DnsResourceRecord authorityRecords in response.Authority)
                            {
                                if ((authorityRecords.Type == DnsResourceRecordType.NS) && (question.Name.Equals(authorityRecords.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authorityRecords.Name, StringComparison.OrdinalIgnoreCase)))
                                {
                                    cachableRecords.Add(authorityRecords);

                                    string nsDomain = (authorityRecords.RDATA as DnsNSRecord).NSDomainName;
                                    if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                    {
                                        foreach (DnsResourceRecord record in response.Additional)
                                        {
                                            if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                                cachableRecords.Add(record);
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
                if (response.Answer.Length == 0)
                {
                    //empty response with no authority
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = null;

                        switch (response.Header.RCODE)
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
            if (response.Header.RCODE == DnsResponseCode.NoError)
            {
                if ((response.Question.Length == 1) && (response.Question[0].Type == DnsResourceRecordType.ANY))
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

                            DnsResourceRecord record = new DnsResourceRecord(question.Name, DnsResourceRecordType.ANY, question.Class, _negativeRecordTtl, new DnsANYRecord(answerRecords.ToArray()));
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

            readonly DnsResourceRecord[] _records;

            #endregion

            #region constructor

            public DnsANYRecord(DnsResourceRecord[] records)
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
                return "[MultipleRecords: " + _records.Length + "]";
            }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
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

            public DnsResourceRecord[] Records
            { get { return _records; } }

            #endregion
        }

        public class DnsFailureRecord : DnsResourceRecordData
        {
            #region variables

            DnsResponseCode _rcode;

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
                if (ReferenceEquals(null, obj))
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
    }
}
