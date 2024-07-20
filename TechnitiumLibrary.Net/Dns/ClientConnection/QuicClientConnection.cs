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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
#pragma warning disable CA2252 // This API requires opting into preview features
#pragma warning disable CA1416 // Validate platform compatibility

    public enum DnsOverQuicErrorCodes : long
    {
        /// <summary>
        /// No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
        /// </summary>
        DOQ_NO_ERROR = 0,

        /// <summary>
        /// The DoQ implementation encountered an internal error and is incapable of pursuing the transaction or the connection.
        /// </summary>
        DOQ_INTERNAL_ERROR = 1,

        /// <summary>
        /// The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
        /// </summary>
        DOQ_PROTOCOL_ERROR = 2,

        /// <summary>
        /// A DoQ client uses this to signal that it wants to cancel an outstanding transaction.
        /// </summary>
        DOQ_REQUEST_CANCELLED = 3,

        /// <summary>
        /// A DoQ implementation uses this to signal when closing a connection due to excessive load.
        /// </summary>
        DOQ_EXCESSIVE_LOAD = 4,

        /// <summary>
        /// A DoQ implementation uses this in the absence of a more specific error code.
        /// </summary>
        DOQ_UNSPECIFIED_ERROR = 5,

        /// <summary>
        /// An alternative error code used for tests.
        /// </summary>
        DOQ_ERROR_RESERVED = 0xd098ea5e
    }

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
            : base(server, proxy)
        {
            if (server.Protocol != DnsTransportProtocol.Quic)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));
        }

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
                IPEndPoint remoteEP;

                if (_proxy is null)
                {
                    if (_server.IsIPEndPointStale)
                        await _server.RecursiveResolveIPAddressAsync(cancellationToken: cancellationToken);

                    remoteEP = _server.IPEndPoint;
                }
                else
                {
                    if (!await _proxy.IsUdpAvailableAsync(cancellationToken))
                        throw new DnsClientException("Unable to connect: The configured proxy server does not support UDP transport required by QUIC protocol.");

                    if ((_udpTunnelProxy is null) || _udpTunnelProxy.IsBroken)
                        _udpTunnelProxy = await _proxy.CreateUdpTunnelProxyAsync(_server.EndPoint, cancellationToken);

                    remoteEP = _udpTunnelProxy.TunnelEndPoint;
                }

                QuicClientConnectionOptions connectionOptions = new QuicClientConnectionOptions()
                {
                    RemoteEndPoint = remoteEP,
                    DefaultCloseErrorCode = (long)DnsOverQuicErrorCodes.DOQ_NO_ERROR,
                    DefaultStreamErrorCode = (long)DnsOverQuicErrorCodes.DOQ_REQUEST_CANCELLED,
                    MaxInboundUnidirectionalStreams = 0,
                    MaxInboundBidirectionalStreams = 0,
                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        ApplicationProtocols = new List<SslApplicationProtocol>() { new SslApplicationProtocol("doq") },
                        TargetHost = _server.Host
                    }
                };

                if (_proxy is null)
                {
                    switch (remoteEP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            Tuple<IPEndPoint, byte[]> ipv4SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv4SourceEP();
                            if (ipv4SourceEP is not null)
                                connectionOptions.LocalEndPoint = ipv4SourceEP.Item1;

                            break;

                        case AddressFamily.InterNetworkV6:
                            Tuple<IPEndPoint, byte[]> ipv6SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv6SourceEP();
                            if (ipv6SourceEP is not null)
                                connectionOptions.LocalEndPoint = ipv6SourceEP.Item1;

                            break;
                    }
                }

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
                //serialize and send request with FIN flag
                using (MemoryStream mS = new MemoryStream(64))
                {
                    mS.Position = 2;
                    request.WriteTo(mS);

                    long datagramLength = mS.Length - 2L;
                    if (datagramLength > ushort.MaxValue)
                        throw new InvalidOperationException();

                    mS.Position = 0;
                    DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(datagramLength), mS);
                    mS.Position = 0;

                    //write with FIN
                    await quicStream.WriteAsync(mS.GetBuffer().AsMemory(0, (int)mS.Length), true, cancellationToken);
                }

                if ((request.Question.Count > 0) && (request.Question[0].Type == DnsResourceRecordType.AXFR))
                {
                    //read zone transfer response
                    DnsDatagram firstResponse = null;
                    DnsDatagram lastResponse = null;
                    MemoryStream sharedBuffer = new MemoryStream(4096);
                    bool isFirstResponse = false;

                    while (true)
                    {
                        DnsDatagram response = await DnsDatagram.ReadFromTcpAsync(quicStream, sharedBuffer, cancellationToken);

                        if (firstResponse is null)
                        {
                            firstResponse = response;
                            isFirstResponse = true;
                        }
                        else
                        {
                            lastResponse.NextDatagram = response;
                        }

                        lastResponse = response;

                        if ((response.Answer.Count == 0) || ((response.Answer[response.Answer.Count - 1].Type == DnsResourceRecordType.SOA) && ((response.Answer.Count > 1) || !isFirstResponse)))
                            break;
                    }

                    return firstResponse;
                }
                else
                {
                    //read standard response
                    return await DnsDatagram.ReadFromTcpAsync(quicStream, 512, cancellationToken);
                }
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

                Task<DnsDatagram> task;

                //query and wait for response with timeout
                using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                    {
                        task = QuicQueryAsync(request, quicConnection, timeoutCancellationTokenSource.Token);

                        if (await Task.WhenAny(task, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != task)
                        {
                            timeoutCancellationTokenSource.Cancel(); //to stop running task
                            continue; //request timed out; retry
                        }
                    }

                    timeoutCancellationTokenSource.Cancel(); //to stop delay task
                }

                DnsDatagram response;

                try
                {
                    response = await task;
                }
                catch (ObjectDisposedException)
                {
                    //ensure existing connection is disposed to allow reconnection later
                    await quicConnection.DisposeAsync();
                    _quicConnection = null;
                    _udpTunnelProxy?.Dispose();

                    if (retry == 1)
                    {
                        //quic connection was disposed on first attempt; retry to reconnect
                        retry = 0;
                        continue;
                    }

                    throw;
                }
                catch (QuicException ex)
                {
                    //close existing connection to allow reconnection later
                    await quicConnection.DisposeAsync();
                    _quicConnection = null;
                    _udpTunnelProxy?.Dispose();

                    if ((ex.QuicError == QuicError.ConnectionIdle) && (retry == 1))
                    {
                        //connection idle on first attempt; retry to reconnect
                        retry = 0;
                        continue;
                    }

                    throw;
                }

                stopwatch.Stop();

                response.SetMetadata(_server, stopwatch.Elapsed.TotalMilliseconds);

                ValidateResponse(request, response);

                return response;
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
