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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Quic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility
    public class HttpsClientConnection : DnsClientConnection
    {
        #region variables

        readonly HttpClient _httpClient;
        UdpTunnelProxy _udpTunnelProxy;

        bool _pooled;
        DateTime _lastQueried;

        #endregion

        #region constructor

        public HttpsClientConnection(NameServerAddress server, NetProxy proxy)
            : base(server, proxy)
        {
            if (server.Protocol != DnsTransportProtocol.Https)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));

            SocketsHttpHandler handler = new SocketsHttpHandler();
            handler.EnableMultipleHttp2Connections = true;
            handler.UseProxy = false;

            if (_proxy is null)
            {
                handler.ConnectCallback += ConnectCallback;
            }
            else
            {
                if (_server.DoHEndPoint.Scheme.Equals("h3", StringComparison.OrdinalIgnoreCase))
                    handler.AllowAutoRedirect = false; //disable redirect since next call may bypass proxy tunnel
                else
                    handler.ConnectCallback += ProxyConnectCallback;
            }

            _httpClient = new HttpClient(handler);
            _httpClient.DefaultRequestHeaders.Add("accept", "application/dns-message");
            _httpClient.DefaultRequestHeaders.Add("user-agent", "DoH client");
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_pooled)
            {
                _httpClient?.Dispose();
                _udpTunnelProxy?.Dispose();
            }
        }

        protected override ValueTask DisposeAsyncCore()
        {
            if (!_pooled)
            {
                _httpClient?.Dispose();
                _udpTunnelProxy?.Dispose();
            }

            return ValueTask.CompletedTask;
        }

        #endregion

        #region private

        private async ValueTask<Stream> ConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            IPEndPoint remoteEP;

            if (_server.DoHEndPoint.Host.Equals(context.DnsEndPoint.Host, StringComparison.OrdinalIgnoreCase))
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(cancellationToken: cancellationToken);

                if (_server.IPEndPoint.Port == context.DnsEndPoint.Port)
                    remoteEP = _server.IPEndPoint;
                else
                    remoteEP = new IPEndPoint(_server.IPEndPoint.Address, context.DnsEndPoint.Port);
            }
            else
            {
                remoteEP = await EndPointExtensions.GetEndPoint(context.DnsEndPoint.Host, context.DnsEndPoint.Port).GetIPEndPointAsync(_server.IPEndPoint is null ? AddressFamily.InterNetwork : _server.IPEndPoint.AddressFamily, true, cancellationToken);
            }

            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    Tuple<IPEndPoint, byte[]> ipv4SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv4SourceEP();
                    if (ipv4SourceEP is not null)
                    {
                        if (ipv4SourceEP.Item2 is not null)
                            socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, ipv4SourceEP.Item2);

                        socket.Bind(ipv4SourceEP.Item1);
                    }

                    break;

                case AddressFamily.InterNetworkV6:
                    Tuple<IPEndPoint, byte[]> ipv6SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv6SourceEP();
                    if (ipv6SourceEP is not null)
                    {
                        if (ipv6SourceEP.Item2 is not null)
                            socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, ipv6SourceEP.Item2);

                        socket.Bind(ipv6SourceEP.Item1);
                    }

                    break;
            }

            await socket.ConnectAsync(remoteEP, cancellationToken);

            socket.NoDelay = true;

            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 2);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            return new NetworkStream(socket, true);
        }

        private async ValueTask<Stream> ProxyConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            EndPoint remoteEP;

            if (!_server.IsIPEndPointStale && _server.DoHEndPoint.Host.Equals(context.DnsEndPoint.Host, StringComparison.OrdinalIgnoreCase))
            {
                if (_server.IPEndPoint.Port == context.DnsEndPoint.Port)
                    remoteEP = _server.IPEndPoint;
                else
                    remoteEP = new IPEndPoint(_server.IPEndPoint.Address, context.DnsEndPoint.Port);
            }
            else
            {
                remoteEP = EndPointExtensions.GetEndPoint(context.DnsEndPoint.Host, context.DnsEndPoint.Port);
            }

            Socket socket = await _proxy.ConnectAsync(remoteEP, cancellationToken);

            return new NetworkStream(socket, true);
        }

        private async Task<HttpRequestMessage> GetHttpRequestAsync(byte[] requestBuffer, CancellationToken cancellationToken)
        {
            bool isH3 = _server.DoHEndPoint.Scheme.Equals("h3", StringComparison.OrdinalIgnoreCase);
            Uri queryUri;
            Version httpVersion;
            HttpVersionPolicy httpVersionPolicy;

            if (_proxy is null)
            {
                httpVersion = HttpVersion.Version30;

                if (isH3)
                {
                    queryUri = new Uri("https://" + _server.DoHEndPoint.Authority + _server.DoHEndPoint.PathAndQuery);
                    httpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
                }
                else
                {
                    queryUri = _server.DoHEndPoint;
                    httpVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                }
            }
            else
            {
                if (isH3)
                {
                    if (!await _proxy.IsUdpAvailableAsync(cancellationToken))
                        throw new DnsClientException("Unable to connect: The configured proxy server does not support UDP transport required by HTTP/3 protocol.");

                    if ((_udpTunnelProxy is null) || _udpTunnelProxy.IsBroken)
                        _udpTunnelProxy = await _proxy.CreateUdpTunnelProxyAsync(_server.EndPoint, cancellationToken);

                    queryUri = new Uri("https://" + _udpTunnelProxy.TunnelEndPoint + _server.DoHEndPoint.PathAndQuery);
                    httpVersion = HttpVersion.Version30;
                    httpVersionPolicy = HttpVersionPolicy.RequestVersionExact;
                }
                else
                {
                    queryUri = _server.DoHEndPoint;
                    httpVersion = HttpVersion.Version20;
                    httpVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                }
            }

            HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, queryUri);

            httpRequest.Version = httpVersion;
            httpRequest.VersionPolicy = httpVersionPolicy;

            if ((_proxy is not null) && isH3)
                httpRequest.Headers.Host = _server.DoHEndPoint.Authority; //override host header since URI now has udp tunnel end point

            httpRequest.Content = new ByteArrayContent(requestBuffer);
            httpRequest.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            return httpRequest;
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            _lastQueried = DateTime.UtcNow;

            //serialize request
            byte[] requestBuffer;

            using (MemoryStream mS = new MemoryStream(32))
            {
                request.WriteTo(mS);
                requestBuffer = mS.ToArray();
            }

            //DoH wire format request
            Stopwatch stopwatch = new Stopwatch();

            stopwatch.Start();

            bool quicHostUnreachableRetryDone = false;
            int retry = 0;
            while (retry < retries) //retry loop
            {
                cancellationToken.ThrowIfCancellationRequested();

                retry++;

                Task<HttpResponseMessage> task;

                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                    {
                        task = _httpClient.SendAsync(await GetHttpRequestAsync(requestBuffer, timeoutCancellationTokenSource.Token), timeoutCancellationTokenSource.Token);

                        if (await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != task)
                        {
                            timeoutCancellationTokenSource.Cancel(); //to stop running task
                            continue; //request timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }
                }

                HttpResponseMessage httpResponse;

                try
                {
                    httpResponse = await task;
                }
                catch (HttpRequestException ex)
                {
                    if ((retry == 1) && (_udpTunnelProxy is not null))
                    {
                        if (ex.InnerException is SocketException ex1)
                        {
                            switch (ex1.SocketErrorCode)
                            {
                                case SocketError.HostUnreachable:
                                    if (!quicHostUnreachableRetryDone)
                                    {
                                        //host unreachable on first attempt; retry to reconnect
                                        retry = 0;
                                        quicHostUnreachableRetryDone = true;
                                    }
                                    else
                                    {
                                        //close existing connection to allow reconnection later
                                        _udpTunnelProxy.Dispose();
                                    }

                                    continue;
                            }
                        }
                        else if (ex.InnerException is QuicException ex2)
                        {
                            switch (ex2.QuicError)
                            {
                                case QuicError.ConnectionIdle:
                                    //close existing connection to allow reconnection later
                                    _udpTunnelProxy.Dispose();

                                    //connection idle on first attempt; retry to reconnect
                                    retry = 0;
                                    continue;
                            }
                        }
                    }

                    throw;
                }

                stopwatch.Stop();
                httpResponse.EnsureSuccessStatusCode();

                byte[] responseBuffer = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);

                //parse response
                using (MemoryStream mS = new MemoryStream(responseBuffer, false))
                {
                    DnsDatagram response = DnsDatagram.ReadFrom(mS);

                    response.SetMetadata(_server, stopwatch.Elapsed.TotalMilliseconds);

                    ValidateResponse(request, response);

                    return response;
                }
            }

            throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out for name server [" + _server.ToString() + "].");
        }

        #endregion

        #region properties

        internal DateTime LastQueried
        { get { return _lastQueried; } }

        internal bool Pooled
        {
            get { return _pooled; }
            set { _pooled = value; }
        }

        #endregion
    }

#pragma warning restore CA2252 // This API requires opting into preview features
#pragma warning restore CA1416 // Validate platform compatibility
}
