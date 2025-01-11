/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    class ResolverNsRevalidationDnsCache : IDnsCache
    {
        #region variables

        readonly IDnsCache _cache;
        readonly DnsQuestionRecord _revalidationQuestion;

        #endregion

        #region constructor

        public ResolverNsRevalidationDnsCache(IDnsCache cache, DnsQuestionRecord revalidationQuestion)
        {
            _cache = cache;
            _revalidationQuestion = revalidationQuestion;
        }

        #endregion

        #region public

        public Task<DnsDatagram> QueryClosestDelegationAsync(DnsDatagram request)
        {
            return _cache.QueryClosestDelegationAsync(request);
        }

        public Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
        {
            if (_revalidationQuestion.Equals(request.Question[0]))
            {
                string parentZone = DnsCache.GetParentZone(_revalidationQuestion.Name);
                if (parentZone is null)
                    return Task.FromResult<DnsDatagram>(null); //parent zone is root

                //return the closest name servers for parent zone
                return _cache.QueryClosestDelegationAsync(new DnsDatagram(request.Identifier, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(parentZone, DnsResourceRecordType.A, DnsClass.IN) }));
            }

            return _cache.QueryAsync(request, serveStale, findClosestNameServers, resetExpiry);
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null)
        {
            _cache.CacheResponse(response, isDnssecBadCache, zoneCut);
        }

        #endregion
    }
}
