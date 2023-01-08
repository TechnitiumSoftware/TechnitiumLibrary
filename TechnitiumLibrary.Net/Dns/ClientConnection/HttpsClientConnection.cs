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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class HttpsClientConnection : DnsClientConnection
    {
        #region variables

        readonly HttpClient _httpClient;

        bool _pooled;
        DateTime _lastQueried;

        #endregion

        #region constructor

        public HttpsClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Https, server, proxy)
        {
            if (proxy is null)
            {
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.EnableMultipleHttp2Connections = true;
                handler.UseProxy = false;

                _httpClient = new HttpClient(handler);
            }
            else
            {
                SocketsHttpHandler handler = new SocketsHttpHandler();
                handler.EnableMultipleHttp2Connections = true;
                handler.Proxy = proxy;

                _httpClient = new HttpClient(handler);
            }

            _httpClient.DefaultRequestHeaders.Add("accept", "application/dns-message");

            if (_server.DoHEndPoint.IsDefaultPort)
                _httpClient.DefaultRequestHeaders.Add("host", _server.DoHEndPoint.Host);
            else
                _httpClient.DefaultRequestHeaders.Add("host", _server.DoHEndPoint.Host + ":" + _server.DoHEndPoint.Port);

            _httpClient.DefaultRequestHeaders.Add("user-agent", "DoH client");
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_pooled)
                _httpClient?.Dispose();
        }

        protected override ValueTask DisposeAsyncCore()
        {
            if (!_pooled)
                _httpClient?.Dispose();

            return ValueTask.CompletedTask;
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            _lastQueried = DateTime.UtcNow;

            async Task<HttpRequestMessage> GetHttpRequest()
            {
                //serialize request
                byte[] requestBuffer;

                using (MemoryStream mS = new MemoryStream(32))
                {
                    request.WriteTo(mS);
                    requestBuffer = mS.ToArray();
                }

                Uri queryUri;

                if (_proxy == null)
                {
                    if (_server.IsIPEndPointStale)
                        await _server.RecursiveResolveIPAddressAsync(null, null, false, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, false, 2, 2000, cancellationToken);

                    queryUri = new Uri(_server.DoHEndPoint.Scheme + "://" + _server.IPEndPoint.ToString() + _server.DoHEndPoint.PathAndQuery);
                }
                else
                {
                    if (_server.IPEndPoint == null)
                        queryUri = _server.DoHEndPoint;
                    else
                        queryUri = new Uri(_server.DoHEndPoint.Scheme + "://" + _server.IPEndPoint.ToString() + _server.DoHEndPoint.PathAndQuery);
                }

                HttpRequestMessage httpRequest = new HttpRequestMessage(HttpMethod.Post, queryUri);
                httpRequest.Content = new ByteArrayContent(requestBuffer);
                httpRequest.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                httpRequest.Version = HttpVersion.Version30;
                httpRequest.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;

                return httpRequest;
            }

            //DoH wire format request
            Stopwatch stopwatch = new Stopwatch();

            stopwatch.Start();

            int retry = 0;
            while (retry < retries) //retry loop
            {
                retry++;

                if (cancellationToken.IsCancellationRequested)
                    return await Task.FromCanceled<DnsDatagram>(cancellationToken); //task cancelled

                Task<HttpResponseMessage> task = _httpClient.SendAsync(await GetHttpRequest(), cancellationToken);

                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                    {
                        if (await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != task)
                            continue; //request timed out; retry
                    }

                    timeoutCancellationTokenSource.Cancel(); //to stop delay task
                }

                HttpResponseMessage httpResponse = await task;

                stopwatch.Stop();
                httpResponse.EnsureSuccessStatusCode();

                byte[] responseBuffer = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);

                //parse response
                using (MemoryStream mS = new MemoryStream(responseBuffer, false))
                {
                    DnsDatagram response = DnsDatagram.ReadFrom(mS);

                    response.SetMetadata(_server, _protocol, stopwatch.Elapsed.TotalMilliseconds);

                    ValidateResponse(request, response);

                    return response;
                }
            }

            throw new DnsClientNoResponseException("DnsClient failed to resolve the request: request timed out.");
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
}
