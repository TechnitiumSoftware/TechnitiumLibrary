/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
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

        readonly MemoryStream _sendBuffer = new MemoryStream(32);
        readonly MemoryStream _recvBuffer = new MemoryStream(64);

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

        private async Task<Stream> GetConnectionAsync()
        {
            if (_tcpStream != null)
                return _tcpStream;

            Socket socket;

            if (_proxy == null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync();

                socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(_server.IPEndPoint);
            }
            else
            {
                socket = await _proxy.ConnectAsync(_server.EndPoint);
            }

            socket.NoDelay = true;

            _socket = socket;
            _tcpStream = await GetNetworkStreamAsync(socket);

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

                    //signal waiting thread of response
                    if (_transactions.TryGetValue(response.Identifier, out Transaction transaction))
                    {
                        transaction.Stopwatch.Stop();

                        response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, response.Size, transaction.Stopwatch.Elapsed.TotalMilliseconds));

                        transaction.ResponseTask.TrySetResult(response);
                    }
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

                    foreach (Transaction transaction in _transactions.Values)
                    {
                        transaction.Stopwatch.Stop();
                        transaction.ResponseTask.SetException(ex);
                    }

                    _transactions.Clear();
                }
                finally
                {
                    _sendRequestSemaphore.Release();
                }
            }
        }

        private async Task<bool> SendDnsDatagramAsync(DnsDatagram request, int timeout, Transaction transaction)
        {
            if (!await _sendRequestSemaphore.WaitAsync(timeout))
                return false; //timed out

            try
            {
                //add transaction in lock
                while (!_transactions.TryAdd(request.Identifier, transaction))
                    request.SetRandomIdentifier();

                //get connection
                Stream tcpStream = await GetConnectionAsync();

                transaction.Stopwatch.Start();

                //send request
                await request.WriteToTcpAsync(tcpStream, _sendBuffer);
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

        protected virtual Task<Stream> GetNetworkStreamAsync(Socket socket)
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
                    Transaction transaction = new Transaction();

                    Task<bool> sendAsyncTask = SendDnsDatagramAsync(request, timeout, transaction);

                    //wait for request with timeout
                    using (var timeoutCancellationTokenSource = new CancellationTokenSource())
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
                    using (var timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        using (CancellationTokenRegistration ctr = cancellationToken.Register(delegate () { timeoutCancellationTokenSource.Cancel(); }))
                        {
                            if (await Task.WhenAny(new Task[] { transaction.ResponseTask.Task, Task.Delay(timeout, timeoutCancellationTokenSource.Token) }) != transaction.ResponseTask.Task)
                                continue; //timed out; retry
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    DnsDatagram response = await transaction.ResponseTask.Task; //await again for any exception to be rethrown

                    if (response.Identifier != request.Identifier)
                        throw new DnsClientException("Invalid response was received: query ID mismatch.");

                    if (response.Question.Count != request.Question.Count)
                        throw new DnsClientException("Invalid response was received: question count mismatch.");

                    for (int i = 0; i < response.Question.Count; i++)
                    {
                        if (request.Question[i].ZoneCut == null)
                        {
                            if (!response.Question[i].Name.Equals(request.Question[i].Name, StringComparison.Ordinal))
                                throw new DnsClientException("Invalid response was received: QNAME mismatch.");

                            if (response.Question[i].Type != request.Question[i].Type)
                                throw new DnsClientException("Invalid response was received: QTYPE mismatch.");
                        }
                        else
                        {
                            if (!response.Question[i].Name.Equals(request.Question[i].MinimizedName, StringComparison.Ordinal))
                                throw new DnsClientException("Invalid response was received: QNAME mismatch.");

                            if (response.Question[i].Type != request.Question[i].MinimizedType)
                                throw new DnsClientException("Invalid response was received: QTYPE mismatch.");
                        }

                        if (response.Question[i].Class != request.Question[i].Class)
                            throw new DnsClientException("Invalid response was received: QCLASS mismatch.");
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
                        transaction.ResponseTask.TrySetCanceled();
                }
            }

            return null;
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

        class Transaction
        {
            public readonly TaskCompletionSource<DnsDatagram> ResponseTask = new TaskCompletionSource<DnsDatagram>();
            public readonly Stopwatch Stopwatch = new Stopwatch();
        }
    }
}
