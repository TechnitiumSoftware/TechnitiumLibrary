/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

using Newtonsoft.Json;
using System;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.Connection
{
    public class HttpsJsonConnection : DnsConnection
    {
        #region constructor

        public HttpsJsonConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsClientProtocol.Https, server, proxy)
        {
            _timeout = 5000;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            //DoH JSON format request 
            DateTime sentAt = DateTime.UtcNow;
            byte[] responseBuffer;

            using (WebClientEx wC = new WebClientEx())
            {
                wC.AddHeader("accept", "application/dns-json");
                wC.AddHeader("host", _server.DnsOverHttpEndPoint.Host + ":" + _server.DnsOverHttpEndPoint.Port);
                wC.UserAgent = "DoH client";
                wC.Proxy = _proxy;
                wC.Timeout = _timeout;

                Uri queryUri;

                if (_proxy == null)
                {
                    if (_server.IPEndPoint == null)
                        _server.RecursiveResolveIPAddress(new SimpleDnsCache());

                    queryUri = new Uri(_server.DnsOverHttpEndPoint.Scheme + "://" + _server.IPEndPoint.ToString() + _server.DnsOverHttpEndPoint.PathAndQuery);
                }
                else
                {
                    queryUri = _server.DnsOverHttpEndPoint;
                }

                wC.QueryString.Clear();
                wC.QueryString.Add("name", request.Question[0].Name);
                wC.QueryString.Add("type", Convert.ToString(((int)request.Question[0].Type)));

                responseBuffer = wC.DownloadData(queryUri);
            }

            //parse response
            dynamic jsonResponse = JsonConvert.DeserializeObject(Encoding.ASCII.GetString(responseBuffer));

            DnsDatagram response = new DnsDatagram(jsonResponse);
            response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, responseBuffer.Length, (DateTime.UtcNow - sentAt).TotalMilliseconds));

            return response;
        }

        #endregion
    }
}
