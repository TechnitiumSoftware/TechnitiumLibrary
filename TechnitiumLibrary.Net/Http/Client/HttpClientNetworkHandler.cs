/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Http.Client
{
    public enum HttpClientNetworkType
    {
        Default = 0,
        IPv4Only = 1,
        IPv6Only = 2,
        PreferIPv6 = 3
    }

    public class HttpClientNetworkHandler : DelegatingHandler
    {
        #region variables

        static bool _publicIpv6Available;
        static DateTime _publicIpv6AvailableLastCheckedOn;
        const int PUBLIC_IPv6_CHECK_FREQUENCY = 300000;

        readonly SocketsHttpHandler _innerHandler;
        HttpClientNetworkType _networkType = HttpClientNetworkType.Default;
        IDnsClient _dnsClient;
        int _retries = 3;
        bool _allowAutoRedirect;
        int _maxAutomaticRedirections;

        #endregion

        #region constructor

        public HttpClientNetworkHandler(SocketsHttpHandler innerHandler, HttpClientNetworkType networkType = HttpClientNetworkType.Default, IDnsClient dnsClient = null)
            : base(innerHandler)
        {
            _innerHandler = innerHandler;
            _dnsClient = dnsClient ?? new DnsClient((_networkType == HttpClientNetworkType.IPv6Only) || (_networkType == HttpClientNetworkType.PreferIPv6));
            _networkType = networkType;

            _allowAutoRedirect = _innerHandler.AllowAutoRedirect;
            _maxAutomaticRedirections = _innerHandler.MaxAutomaticRedirections;

            if (_innerHandler.AllowAutoRedirect)
                _innerHandler.AllowAutoRedirect = false;
        }

        #endregion

        #region private

        private static bool IsPublicIPv6Available()
        {
            if (!Socket.OSSupportsIPv6)
                return false;

            if (DateTime.UtcNow > _publicIpv6AvailableLastCheckedOn.AddMilliseconds(PUBLIC_IPv6_CHECK_FREQUENCY))
            {
                _publicIpv6Available = NetUtilities.GetDefaultIPv6NetworkInfo() is not null;
                _publicIpv6AvailableLastCheckedOn = DateTime.UtcNow;
            }

            return _publicIpv6Available;
        }

        private async Task<HttpResponseMessage> InternalSendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int retry = 0;

            while (retry++ < _retries)
            {
                try
                {
                    return await base.SendAsync(request, cancellationToken);
                }
                catch (HttpRequestException ex)
                {
                    if (ex.InnerException is SocketException ex2)
                    {
                        switch (ex2.SocketErrorCode)
                        {
                            case SocketError.ConnectionRefused:
                                throw;

                            case SocketError.NetworkUnreachable:
                                if (_publicIpv6Available && (_networkType == HttpClientNetworkType.Default))
                                {
                                    _publicIpv6Available = false;
                                    _publicIpv6AvailableLastCheckedOn = default;
                                }

                                throw;
                        }
                    }

                    if (retry >= _retries)
                        throw;
                }
            }

            throw new InvalidOperationException();
        }

        #endregion

        #region protected

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_innerHandler.AllowAutoRedirect)
                throw new InvalidOperationException("Inner HTTP handler must not be configured to perform auto redirection.");

            HttpResponseMessage response;
            int redirections = 0;

            do
            {
                if (_innerHandler.UseProxy && (_innerHandler.Proxy is not null))
                {
                    //no DNS resolution when proxy is used
                    response = await InternalSendAsync(request, cancellationToken);
                }
                else
                {
                    string host = request.RequestUri.Host;

                    if (IPAddress.TryParse(host, out IPAddress ip))
                    {
                        switch (_networkType)
                        {
                            case HttpClientNetworkType.IPv4Only:
                                if (ip.AddressFamily != AddressFamily.InterNetwork)
                                    throw new HttpRequestException("HttpClient current network type allows only IPv4 access.");

                                break;

                            case HttpClientNetworkType.IPv6Only:
                                if (ip.AddressFamily != AddressFamily.InterNetworkV6)
                                    throw new HttpRequestException("HttpClient current network type allows only IPv6 access.");

                                break;
                        }

                        response = await InternalSendAsync(request, cancellationToken);
                    }
                    else
                    {
                        IReadOnlyList<IPAddress> addresses = null;

                        try
                        {
                            switch (_networkType)
                            {
                                case HttpClientNetworkType.IPv4Only:
                                    addresses = Dns.DnsClient.ParseResponseA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), cancellationToken));
                                    if (addresses.Count < 1)
                                        throw new HttpRequestException("HttpClient could not resolve IPv4 address for host: " + host);

                                    break;

                                case HttpClientNetworkType.IPv6Only:
                                    addresses = Dns.DnsClient.ParseResponseAAAA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken));
                                    if (addresses.Count < 1)
                                        throw new HttpRequestException("HttpClient could not resolve IPv6 address for host: " + host);

                                    break;

                                case HttpClientNetworkType.PreferIPv6:
                                    addresses = Dns.DnsClient.ParseResponseAAAA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken));
                                    if (addresses.Count < 1)
                                    {
                                        addresses = Dns.DnsClient.ParseResponseA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), cancellationToken));
                                        if (addresses.Count < 1)
                                            throw new HttpRequestException("HttpClient could not resolve IP address for host: " + host);
                                    }

                                    break;

                                default:
                                    if (IsPublicIPv6Available())
                                        addresses = Dns.DnsClient.ParseResponseAAAA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken));

                                    if ((addresses is null) || (addresses.Count < 1))
                                    {
                                        addresses = Dns.DnsClient.ParseResponseA(await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), cancellationToken));
                                        if (addresses.Count < 1)
                                            throw new HttpRequestException("HttpClient could not resolve IP address for host: " + host);
                                    }

                                    break;
                            }
                        }
                        catch (DnsClientException ex)
                        {
                            throw new HttpRequestException("HttpClient could not resolve IP address for host: " + host, ex);
                        }

                        switch (addresses[0].AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                request.RequestUri = new Uri(request.RequestUri.Scheme + "://" + addresses[0].ToString() + ":" + request.RequestUri.Port + request.RequestUri.PathAndQuery);
                                break;

                            case AddressFamily.InterNetworkV6:
                                request.RequestUri = new Uri(request.RequestUri.Scheme + "://[" + addresses[0].ToString() + "]:" + request.RequestUri.Port + request.RequestUri.PathAndQuery);
                                break;

                            default:
                                throw new NotSupportedException("AddressFamily was not supported.");
                        }

                        if (request.RequestUri.IsDefaultPort)
                            request.Headers.Host = host;
                        else
                            request.Headers.Host = host + ":" + request.RequestUri.Port;

                        response = await InternalSendAsync(request, cancellationToken);
                    }
                }

                switch (response.StatusCode)
                {
                    case HttpStatusCode.MovedPermanently:
                    case HttpStatusCode.PermanentRedirect:
                    case HttpStatusCode.Found:
                    case HttpStatusCode.RedirectKeepVerb:
                        request.RequestUri = response.Headers.Location;
                        break;

                    case HttpStatusCode.RedirectMethod:
                        request.Method = HttpMethod.Get;
                        request.RequestUri = response.Headers.Location;
                        request.Content = null;
                        break;

                    default:
                        return response;
                }
            }
            while (_allowAutoRedirect && (redirections++ < _maxAutomaticRedirections));

            return response;
        }

        #endregion

        #region properties

        public HttpClientNetworkType NetworkType
        {
            get { return _networkType; }
            set { _networkType = value; }
        }

        public IDnsClient DnsClient
        {
            get { return _dnsClient; }
            set { _dnsClient = value; }
        }

        public int Retries
        {
            get { return _retries; }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException(nameof(Retries), "HttpClient retries value cannot be less than 1.");

                _retries = value;
            }
        }

        public bool AllowAutoRedirect
        {
            get { return _allowAutoRedirect; }
            set { _allowAutoRedirect = value; }
        }

        public int MaxAutomaticRedirections
        {
            get { return _maxAutomaticRedirections; }
            set { _maxAutomaticRedirections = value; }
        }

        #endregion
    }
}
