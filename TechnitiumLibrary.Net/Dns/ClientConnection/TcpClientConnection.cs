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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class TcpClientConnection : DnsClientConnection
    {
        #region variables

        const int ASYNC_RECEIVE_TIMEOUT = 120000;

        Socket _socket;
        Stream _tcpStream;

        readonly ConcurrentDictionary<ushort, Transaction> _transactions = new ConcurrentDictionary<ushort, Transaction>();

        readonly MemoryStream _sendBuffer = new MemoryStream(64);
        readonly MemoryStream _recvBuffer = new MemoryStream(4096);

        readonly SemaphoreSlim _sendRequestSemaphore = new SemaphoreSlim(1, 1);

        bool _pooled;
        DateTime _lastQueried;

        #endregion

        #region constructor

        public TcpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(server, proxy)
        {
            if (server.Protocol != DnsTransportProtocol.Tcp)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));
        }

        protected TcpClientConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
            : base(server, proxy)
        {
            if (server.Protocol != protocol)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_pooled)
            {
                if (_socket is not null)
                {
                    try
                    {
                        if (_socket.Connected)
                            _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _socket.Dispose();
                }

                _tcpStream?.Dispose();

                _sendBuffer?.Dispose();

                _recvBuffer?.Dispose();

                _sendRequestSemaphore?.Dispose();
            }
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            if (!_pooled)
            {
                if (_socket is not null)
                {
                    try
                    {
                        if (_socket.Connected)
                            _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _socket.Dispose();
                }

                if (_tcpStream is not null)
                    await _tcpStream.DisposeAsync();

                if (_sendBuffer is not null)
                    await _sendBuffer.DisposeAsync();

                if (_recvBuffer is not null)
                    await _recvBuffer.DisposeAsync();

                _sendRequestSemaphore?.Dispose();
            }
        }

        #endregion

        #region private

        private async Task<Stream> GetConnectionAsync(CancellationToken cancellationToken)
        {
            if (_tcpStream is not null)
            {
                if ((_socket is not null) && _socket.Connected)
                    return _tcpStream;

                _tcpStream.Dispose();
            }

            Socket socket;

            if (_proxy is null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(cancellationToken: cancellationToken);

                socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                switch (_server.IPEndPoint.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        Tuple<IPEndPoint, byte[]> ipv4SourceEP = IPAddress.IsLoopback(_server.IPEndPoint.Address) ? null : GetIPv4SourceEP();
                        if (ipv4SourceEP is not null)
                        {
                            if (ipv4SourceEP.Item2 is not null)
                                socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, ipv4SourceEP.Item2);

                            socket.Bind(ipv4SourceEP.Item1);
                        }

                        break;

                    case AddressFamily.InterNetworkV6:
                        Tuple<IPEndPoint, byte[]> ipv6SourceEP = IPAddress.IsLoopback(_server.IPEndPoint.Address) ? null : GetIPv6SourceEP();
                        if (ipv6SourceEP is not null)
                        {
                            if (ipv6SourceEP.Item2 is not null)
                                socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, ipv6SourceEP.Item2);

                            socket.Bind(ipv6SourceEP.Item1);
                        }

                        break;
                }

                await socket.ConnectAsync(_server.IPEndPoint, cancellationToken);
            }
            else
            {
                socket = await _proxy.ConnectAsync(_server.EndPoint, cancellationToken);
            }

            socket.NoDelay = true;

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 2);
                socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3); //IPPROTO_TCP.TCP_KEEPCNT - supported with Windows 10, version 1703 and above
            }
            catch
            { }

            _socket = socket;
            _tcpStream = await GetNetworkStreamAsync(socket, cancellationToken);

            _ = ReadDnsDatagramAsync(_tcpStream);

            return _tcpStream;
        }

        private async Task ReadDnsDatagramAsync(Stream tcpStream)
        {
            try
            {
                while (true)
                {
                    //read response datagram
                    DnsDatagram response = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                    {
                        return DnsDatagram.ReadFromTcpAsync(tcpStream, _recvBuffer, cancellationToken1);
                    }, ASYNC_RECEIVE_TIMEOUT, CancellationToken.None);

                    //signal response
                    if (_transactions.TryGetValue(response.Identifier, out Transaction transaction))
                        transaction.SetResponse(response, _server);
                }
            }
            catch (Exception ex)
            {
                await _sendRequestSemaphore.WaitAsync(CancellationToken.None);
                try
                {
                    //ensure current tcp stream is same and not replaced by reconnection attempt
                    if (ReferenceEquals(tcpStream, _tcpStream))
                    {
                        _tcpStream.Dispose();
                        _tcpStream = null;

                        foreach (KeyValuePair<ushort, Transaction> transaction in _transactions)
                            transaction.Value.SetException(ex);

                        _transactions.Clear();
                    }
                }
                finally
                {
                    _sendRequestSemaphore.Release();
                }
            }
        }

        private async Task<bool> SendDnsDatagramAsync(DnsDatagram request, int timeout, Transaction transaction, CancellationToken cancellationToken)
        {
            if (!await _sendRequestSemaphore.WaitAsync(timeout, cancellationToken))
                return false; //timed out

            try
            {
                //add transaction in lock
                while (!_transactions.TryAdd(request.Identifier, transaction))
                    request.SetRandomIdentifier();

                //get connection
                Stream tcpStream = await GetConnectionAsync(cancellationToken);

                //send request
                await request.WriteToTcpAsync(tcpStream, _sendBuffer, CancellationToken.None); //no cancellation token to prevent corrupting tcp stream data
                tcpStream.Flush();

                return true;
            }
            finally
            {
                _sendRequestSemaphore.Release();
            }
        }

        #endregion

        #region protected

        protected virtual Task<Stream> GetNetworkStreamAsync(Socket socket, CancellationToken cancellationToken)
        {
            return Task.FromResult<Stream>(new NetworkStream(socket, true));
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            _lastQueried = DateTime.UtcNow;

            Task<bool> firstSendAsyncTask = null;

            int retry = 0;
            while (retry < retries) //retry loop
            {
                cancellationToken.ThrowIfCancellationRequested();

                retry++;

                try
                {
                    Transaction transaction = new Transaction(request);

                    Task<bool> sendAsyncTask = SendDnsDatagramAsync(request, timeout, transaction, cancellationToken);
                    if (firstSendAsyncTask is null)
                        firstSendAsyncTask = sendAsyncTask;

                    //wait for request with timeout
                    using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                        {
                            if (await Task.WhenAny(sendAsyncTask, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != sendAsyncTask)
                                continue; //send timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    if (!await sendAsyncTask)
                        continue; //semaphone wait timed out; retry

                    //wait for response with timeout
                    using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        await using (CancellationTokenRegistration ctr = cancellationToken.Register(timeoutCancellationTokenSource.Cancel))
                        {
                            if (await Task.WhenAny(transaction.Response, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) != transaction.Response)
                                continue; //timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    DnsDatagram response = await transaction.Response; //await again for any exception to be rethrown

                    ValidateResponse(request, response);

                    return response;
                }
                catch (IOException)
                {
                    if (retry == retries)
                        throw;

                    //retry
                }
                catch (TimeoutException)
                {
                    //read response task timed out; retry
                }
                catch (ObjectDisposedException)
                {
                    //connection is closed; retry
                }
                finally
                {
                    if (_transactions.TryRemove(request.Identifier, out Transaction transaction))
                        transaction.Dispose();
                }
            }

            if ((firstSendAsyncTask is not null) && firstSendAsyncTask.IsFaulted)
                await firstSendAsyncTask; //await to throw relevent exception

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

        class Transaction : IDisposable
        {
            #region variables

            readonly bool _isZoneTransferRequest;
            readonly bool _isIXFR;

            readonly Stopwatch _stopwatch = new Stopwatch();
            readonly TaskCompletionSource<DnsDatagram> _responseTask = new TaskCompletionSource<DnsDatagram>();

            DnsDatagram _firstResponse;
            DnsDatagram _lastResponse;

            #endregion

            #region constructor

            public Transaction(DnsDatagram request)
            {
                _isZoneTransferRequest = request.IsZoneTransfer;
                if (_isZoneTransferRequest)
                    _isIXFR = request.Question[0].Type == DnsResourceRecordType.IXFR;

                _stopwatch.Start();
            }

            #endregion

            #region IDisposable

            bool _disposed;

            protected void Dispose(bool disposing)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_responseTask is not null)
                        _responseTask.TrySetCanceled(CancellationToken.None);
                }

                _disposed = true;
            }

            public void Dispose()
            {
                Dispose(true);
            }

            #endregion

            #region public

            public void SetResponse(DnsDatagram response, NameServerAddress server)
            {
                if (_isZoneTransferRequest)
                {
                    bool isFirstResponse = false;
                    if (_firstResponse is null)
                    {
                        _firstResponse = response;
                        isFirstResponse = true;
                    }
                    else
                    {
                        _lastResponse.NextDatagram = response;
                    }

                    _lastResponse = response;

                    if (
                        (_lastResponse.Answer.Count == 0) || //empty response
                        (_isIXFR && (_lastResponse.Answer.Count == 1) && (_lastResponse.Answer[0].Type == DnsResourceRecordType.SOA)) || //IXFR not modified response
                        ((_lastResponse.Answer[_lastResponse.Answer.Count - 1].Type == DnsResourceRecordType.SOA) && ((_lastResponse.Answer.Count > 1) || !isFirstResponse))
                       )
                    {
                        //found last response
                        _stopwatch.Stop();

                        _firstResponse.SetMetadata(server, _stopwatch.Elapsed.TotalMilliseconds);

                        _responseTask.TrySetResult(_firstResponse);
                    }
                }
                else
                {
                    _stopwatch.Stop();

                    response.SetMetadata(server, _stopwatch.Elapsed.TotalMilliseconds);

                    _responseTask.TrySetResult(response);
                }
            }

            public void SetException(Exception ex)
            {
                _responseTask.SetException(ex);
            }

            #endregion

            #region properties

            public Task<DnsDatagram> Response
            { get { return _responseTask.Task; } }

            #endregion
        }
    }
}
