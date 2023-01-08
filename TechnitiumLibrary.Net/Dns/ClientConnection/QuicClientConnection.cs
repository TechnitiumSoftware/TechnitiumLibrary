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
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

    public class QuicClientConnection : DnsClientConnection
    {
        #region variables

        QuicConnection _quicConnection;
        UdpTunnelProxy _udpTunnelProxy;

        bool _pooled;
        DateTime _lastQueried;

        readonly SemaphoreSlim _connectionSemaphore = new SemaphoreSlim(1, 1);

        #endregion

        #region constructor

        public QuicClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Quic, server, proxy)
        { }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_pooled)
            {
                if (_quicConnection is not null)
                {
                    _quicConnection.CloseAsync(0).Sync();
                    _quicConnection.DisposeAsync().Sync();
                }

                _udpTunnelProxy?.Dispose();

                _connectionSemaphore?.Dispose();
            }
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            if (!_pooled)
            {
                if (_quicConnection is not null)
                {
                    await _quicConnection.CloseAsync(0);
                    await _quicConnection.DisposeAsync();
                }

                _udpTunnelProxy?.Dispose();

                _connectionSemaphore?.Dispose();
            }
        }

        #endregion

        #region private

        private async Task<QuicConnection> GetConnectionAsync(int timeout, CancellationToken cancellationToken)
        {
            if (_quicConnection is not null)
                return _quicConnection;

            if (!await _connectionSemaphore.WaitAsync(timeout, cancellationToken))
                return null; //timed out

            if (_quicConnection is not null)
                return _quicConnection;

            try
            {
                EndPoint remoteEP;

                if (_proxy is null)
                {
                    if (_server.IsIPEndPointStale)
                        await _server.RecursiveResolveIPAddressAsync(null, null, false, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, false, 2, 2000, cancellationToken);

                    remoteEP = _server.IPEndPoint;
                }
                else
                {
                    if (!await _proxy.IsUdpAvailableAsync())
                        throw new DnsClientException("The configured proxy server does not support UDP transport required by QUIC protocol.");

                    if ((_udpTunnelProxy is null) || _udpTunnelProxy.IsBroken)
                        _udpTunnelProxy = await _proxy.CreateUdpTunnelProxyAsync(_server.EndPoint, cancellationToken);

                    remoteEP = _udpTunnelProxy.TunnelEndPoint;
                }

                QuicClientConnectionOptions connectionOptions = new QuicClientConnectionOptions();

                connectionOptions.RemoteEndPoint = remoteEP;
                connectionOptions.DefaultCloseErrorCode = 0;
                connectionOptions.DefaultStreamErrorCode = 0;
                connectionOptions.ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    ApplicationProtocols = new List<SslApplicationProtocol>() { new SslApplicationProtocol("doq") }
                };

                Console.WriteLine("Connecting " + remoteEP.ToString());

                _quicConnection = await QuicConnection.ConnectAsync(connectionOptions, cancellationToken);
                return _quicConnection;
            }
            finally
            {
                _connectionSemaphore.Release();
            }
        }

        private static async Task<DnsDatagram> QuicQueryAsync(DnsDatagram request, QuicConnection quicConnection, CancellationToken cancellationToken)
        {
            await using (QuicStream quicStream = await quicConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken))
            {
                await request.WriteToTcpAsync(quicStream, cancellationToken);

                return await DnsDatagram.ReadFromTcpAsync(quicStream, cancellationToken);
            }
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            _lastQueried = DateTime.UtcNow;

            Stopwatch stopwatch = new Stopwatch();

            stopwatch.Start();

            int retry = 0;
            while (retry < retries) //retry loop
            {
                retry++;

                if (cancellationToken.IsCancellationRequested)
                    return await Task.FromCanceled<DnsDatagram>(cancellationToken); //task cancelled

                Task<QuicConnection> quicConnectionTask = GetConnectionAsync(timeout, cancellationToken);

                //wait for connection with timeout
                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                    {
                        if (await Task.WhenAny(quicConnectionTask, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != quicConnectionTask)
                            continue; //request timed out; retry
                    }

                    timeoutCancellationTokenSource.Cancel(); //to stop delay task
                }

                QuicConnection quicConnection = await quicConnectionTask;
                if (quicConnection is null)
                    continue; //semaphone wait timed out; retry

                Task<DnsDatagram> task = QuicQueryAsync(request, quicConnection, cancellationToken);

                //wait for response with timeout
                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                    {
                        if (await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != task)
                            continue; //request timed out; retry
                    }

                    timeoutCancellationTokenSource.Cancel(); //to stop delay task
                }

                DnsDatagram response;

                try
                {
                    response = await task;
                }
                catch (QuicException)
                {
                    //close existing connection to allow reconnection later
                    await _quicConnection.DisposeAsync();
                    _quicConnection = null;
                    _udpTunnelProxy?.Dispose();
                    throw;
                }

                stopwatch.Stop();

                response.SetMetadata(_server, _protocol, stopwatch.Elapsed.TotalMilliseconds);

                ValidateResponse(request, response);

                return response;
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

#pragma warning restore CA2252 // This API requires opting into preview features
#pragma warning restore CA1416 // Validate platform compatibility
}
