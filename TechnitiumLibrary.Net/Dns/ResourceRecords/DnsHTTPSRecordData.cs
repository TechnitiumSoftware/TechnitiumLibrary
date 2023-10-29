/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsHTTPSRecordData : DnsSVCBRecordData
    {
        #region constructors

        public DnsHTTPSRecordData(ushort svcPriority, string targetName, IReadOnlyDictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams)
            : base(svcPriority, targetName, svcParams)
        { }

        public DnsHTTPSRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region internal

        internal new static async Task<DnsHTTPSRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsHTTPSRecordData(rdata);

            ushort svcPriority = ushort.Parse(await zoneFile.PopItemAsync());
            string targetName = await zoneFile.PopDomainAsync();

            Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>();
            string param;
            int i;
            DnsSvcParamKey svcParamKey;
            DnsSvcParamValue svcParamValue;

            do
            {
                param = await zoneFile.PopItemAsync();
                if (param is null)
                    break;

                i = param.IndexOf('=');
                if (i < 0)
                    svcParamKey = Enum.Parse<DnsSvcParamKey>(param.Replace('-', '_'), true);
                else
                    svcParamKey = Enum.Parse<DnsSvcParamKey>(param.Substring(0, i).Replace('-', '_'), true);

                svcParamValue = DnsSvcParamValue.Parse(svcParamKey, param.Substring(i + 1));

                svcParams.Add(svcParamKey, svcParamValue);
            }
            while (true);

            return new DnsHTTPSRecordData(svcPriority, targetName, svcParams);
        }

        #endregion
    }
}
