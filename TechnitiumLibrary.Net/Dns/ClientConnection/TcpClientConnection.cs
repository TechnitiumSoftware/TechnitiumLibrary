/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
            : base(DnsTransportProtocol.Tcp, server, proxy)
        { }

        protected TcpClientConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
            : base(protocol, server, proxy)
        { }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing && !_pooled)
            {
                if (_socket != null)
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

                if (_tcpStream != null)
                    _tcpStream.Dispose();

                if (_sendBuffer != null)
                    _sendBuffer.Dispose();

                if (_recvBuffer != null)
                    _recvBuffer.Dispose();

                if (_sendRequestSemaphore != null)
                    _sendRequestSemaphore.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private async Task<Stream> GetConnectionAsync(CancellationToken cancellationToken)
        {
            if (_tcpStream != null)
                return _tcpStream;

            Socket socket;

            if (_proxy == null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(null, null, false, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, false, 2, 2000, cancellationToken);

                socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(_server.IPEndPoint, cancellationToken);
            }
            else
            {
                socket = await _proxy.ConnectAsync(_server.EndPoint, cancellationToken);
            }

            socket.NoDelay = true;

            _socket = socket;
            _tcpStream = await GetNetworkStreamAsync(socket, cancellationToken);

            _ = ReadDnsDatagramAsync();

            return _tcpStream;
        }

        private async Task ReadDnsDatagramAsync()
        {
            try
            {
                while (true)
                {
                    //read response datagram
                    DnsDatagram response = await DnsDatagram.ReadFromTcpAsync(_tcpStream, _recvBuffer).WithTimeout(ASYNC_RECEIVE_TIMEOUT);

                    //signal response
                    if (_transactions.TryGetValue(response.Identifier, out Transaction transaction))
                        transaction.SetResponse(response, _server, _protocol);
                }
            }
            catch (Exception ex)
            {
                await _sendRequestSemaphore.WaitAsync();
                try
                {
                    if (_tcpStream != null)
                    {
                        _tcpStream.Dispose();
                        _tcpStream = null;
                    }

                    foreach (KeyValuePair<ushort, Transaction> transaction in _transactions)
                        transaction.Value.SetException(ex);

                    _transactions.Clear();
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
                await request.WriteToTcpAsync(tcpStream, _sendBuffer, cancellationToken);
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

            int retry = 0;
            while (retry < retries) //retry loop
            {
                retry++;

                if (cancellationToken.IsCancellationRequested)
                    return await Task.FromCanceled<DnsDatagram>(cancellationToken); //task cancelled

                try
                {
                    Transaction transaction = new Transaction(request.IsZoneTransfer);

                    Task<bool> sendAsyncTask = SendDnsDatagramAsync(request, timeout, transaction, cancellationToken);

                    //wait for request with timeout
                    using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        using (CancellationTokenRegistration ctr = cancellationToken.Register(delegate () { timeoutCancellationTokenSource.Cancel(); }))
                        {
                            if (await Task.WhenAny(new Task[] { sendAsyncTask, Task.Delay(timeout, timeoutCancellationTokenSource.Token) }) != sendAsyncTask)
                                continue; //send timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    if (!await sendAsyncTask)
                        continue; //semaphone wait timed out; retry

                    //wait for response with timeout
                    using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        using (CancellationTokenRegistration ctr = cancellationToken.Register(delegate () { timeoutCancellationTokenSource.Cancel(); }))
                        {
                            if (await Task.WhenAny(new Task[] { transaction.Response, Task.Delay(timeout, timeoutCancellationTokenSource.Token) }) != transaction.Response)
                                continue; //timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    DnsDatagram response = await transaction.Response; //await again for any exception to be rethrown

                    if (response.Identifier != request.Identifier)
                        throw new DnsClientResponseValidationException("Invalid response was received: query ID mismatch.");

                    if (response.Question.Count == request.Question.Count)
                    {
                        for (int i = 0; i < response.Question.Count; i++)
                        {
                            if (request.Question[i].ZoneCut == null)
                            {
                                if (!response.Question[i].Name.Equals(request.Question[i].Name, StringComparison.Ordinal))
                                    throw new DnsClientResponseValidationException("Invalid response was received: QNAME mismatch.");

                                if (response.Question[i].Type != request.Question[i].Type)
                                    throw new DnsClientResponseValidationException("Invalid response was received: QTYPE mismatch.");
                            }
                            else
                            {
                                if (!response.Question[i].Name.Equals(request.Question[i].MinimizedName, StringComparison.Ordinal))
                                    throw new DnsClientResponseValidationException("Invalid response was received: QNAME mismatch.");

                                if (response.Question[i].Type != request.Question[i].MinimizedType)
                                    throw new DnsClientResponseValidationException("Invalid response was received: QTYPE mismatch.");
                            }

                            if (response.Question[i].Class != request.Question[i].Class)
                                throw new DnsClientResponseValidationException("Invalid response was received: QCLASS mismatch.");
                        }
                    }
                    else
                    {
                        if (response.RCODE != DnsResponseCode.FormatError)
                            throw new DnsClientResponseValidationException("Invalid response was received: question count mismatch.");
                    }

                    return response;
                }
                catch (IOException)
                {
                    if (retry == retries)
                        throw;

                    //retry
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

        class Transaction : IDisposable
        {
            #region variables

            readonly bool _isZoneTransferRequest;

            readonly Stopwatch _stopwatch = new Stopwatch();
            readonly TaskCompletionSource<DnsDatagram> _responseTask = new TaskCompletionSource<DnsDatagram>();

            DnsDatagram _firstResponse;
            DnsDatagram _lastResponse;

            #endregion

            #region constructor

            public Transaction(bool isZoneTransferRequest)
            {
                _isZoneTransferRequest = isZoneTransferRequest;

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

            public void SetResponse(DnsDatagram response, NameServerAddress server, DnsTransportProtocol protocol)
            {
                if (_isZoneTransferRequest)
                {
                    if (_firstResponse is null)
                        _firstResponse = response;
                    else
                        _lastResponse.NextDatagram = response;

                    _lastResponse = response;

                    if ((_lastResponse.Answer.Count == 0) || (_lastResponse.Answer[_lastResponse.Answer.Count - 1].Type == DnsResourceRecordType.SOA))
                    {
                        //found last response
                        _stopwatch.Stop();

                        _firstResponse.SetMetadata(server, protocol, _stopwatch.Elapsed.TotalMilliseconds);

                        _responseTask.TrySetResult(_firstResponse);
                    }
                }
                else
                {
                    _stopwatch.Stop();

                    response.SetMetadata(server, protocol, _stopwatch.Elapsed.TotalMilliseconds);

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
