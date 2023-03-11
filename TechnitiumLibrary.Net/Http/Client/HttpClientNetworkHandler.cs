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
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Http.Client
{
    public enum HttpClientNetworkType
    {
        Default = 0,
        IPv4Only = 1,
        IPv6Only = 2
    }

    public class HttpClientNetworkHandler : DelegatingHandler
    {
        #region variables

        HttpClientNetworkType _networkType = HttpClientNetworkType.Default;

        DnsClient _dnsClient;

        #endregion

        #region constructor

        public HttpClientNetworkHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        { }

        #endregion

        #region protected

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            switch (_networkType)
            {
                case HttpClientNetworkType.IPv4Only:
                    if (IPAddress.TryParse(request.RequestUri.Host, out IPAddress ipv4))
                    {
                        if (ipv4.AddressFamily != AddressFamily.InterNetwork)
                            throw new HttpRequestException("HttpClient current network type allows only IPv4 addresses.");

                        return await base.SendAsync(request, cancellationToken);
                    }
                    else
                    {
                        try
                        {
                            if (_dnsClient is null)
                                _dnsClient = new DnsClient();

                            IReadOnlyList<IPAddress> ipAddresses = await _dnsClient.ResolveIPAsync(request.RequestUri.Host, false, cancellationToken);

                            foreach (IPAddress ipAddress in ipAddresses)
                            {
                                if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    request.Headers.Host = request.RequestUri.Host;
                                    request.RequestUri = new Uri(request.RequestUri.Scheme + "://" + ipAddress.ToString() + ":" + request.RequestUri.Port + request.RequestUri.PathAndQuery);
                                    return await base.SendAsync(request, cancellationToken);
                                }
                            }

                            throw new HttpRequestException("HttpClient could not resolve IPv4 address for host: " + request.RequestUri.Host);
                        }
                        catch (DnsClientException ex)
                        {
                            throw new HttpRequestException("HttpClient could not resolve IPv4 address for host: " + request.RequestUri.Host, ex);
                        }
                    }

                case HttpClientNetworkType.IPv6Only:
                    if (IPAddress.TryParse(request.RequestUri.Host, out IPAddress ipv6))
                    {
                        if (ipv6.AddressFamily != AddressFamily.InterNetworkV6)
                            throw new HttpRequestException("HttpClient current network type allows only IPv6 addresses.");

                        return await base.SendAsync(request, cancellationToken);
                    }
                    else
                    {
                        try
                        {
                            if (_dnsClient is null)
                                _dnsClient = new DnsClient();

                            IReadOnlyList<IPAddress> ipAddresses = await _dnsClient.ResolveIPAsync(request.RequestUri.Host, true, cancellationToken);

                            foreach (IPAddress ipAddress in ipAddresses)
                            {
                                if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
                                {
                                    request.Headers.Host = request.RequestUri.Host;
                                    request.RequestUri = new Uri(request.RequestUri.Scheme + "://[" + ipAddress.ToString() + "]:" + request.RequestUri.Port + request.RequestUri.PathAndQuery);
                                    return await base.SendAsync(request, cancellationToken);
                                }
                            }

                            throw new HttpRequestException("HttpClient could not resolve IPv6 address for host: " + request.RequestUri.Host);
                        }
                        catch (DnsClientException ex)
                        {
                            throw new HttpRequestException("HttpClient could not resolve IPv6 address for host: " + request.RequestUri.Host, ex);
                        }
                    }

                default:
                    return await base.SendAsync(request, cancellationToken);
            }
        }

        #endregion

        #region properties

        public HttpClientNetworkType NetworkType
        {
            get { return _networkType; }
            set { _networkType = value; }
        }

        #endregion
    }
}
