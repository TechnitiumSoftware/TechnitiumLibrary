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
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class TcpClientConnection : DnsClientConnection
    {
        #region variables

        const int SOCKET_RECEIVE_TIMEOUT = 10000; //to keep connection alive for reuse

        Stream _tcpStream;
        Thread _readThread;

        readonly ConcurrentDictionary<ushort, Transaction> _transactions = new ConcurrentDictionary<ushort, Transaction>();

        readonly byte[] _lengthBuffer = new byte[2];
        readonly MemoryStream _sendBuffer = new MemoryStream(32);
        readonly MemoryStream _recvBuffer = new MemoryStream(64);

        readonly object _tcpStreamLock = new object();

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

        #region private

        private Stream GetConnection(int timeout)
        {
            if (_tcpStream != null)
                return _tcpStream;

            Socket socket;

            if (_proxy == null)
            {
                if (_server.IPEndPoint == null)
                    _server.RecursiveResolveIPAddress();

                socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                IAsyncResult result = socket.BeginConnect(_server.IPEndPoint, null, null);
                if (!result.AsyncWaitHandle.WaitOne(timeout))
                    throw new SocketException((int)SocketError.TimedOut);

                if (!socket.Connected)
                    throw new SocketException((int)SocketError.ConnectionRefused);
            }
            else
            {
                socket = _proxy.Connect(_server.EndPoint, timeout);
            }

            socket.SendTimeout = timeout;
            socket.ReceiveTimeout = SOCKET_RECEIVE_TIMEOUT;
            socket.SendBufferSize = 512;
            socket.ReceiveBufferSize = 2048;
            socket.NoDelay = true;

            _tcpStream = new WriteBufferedStream(GetNetworkStream(socket), 2048);

            _readThread = new Thread(ReadDnsDatagramAsync);
            _readThread.IsBackground = true;
            _readThread.Start();

            return _tcpStream;
        }

        private void ReadDnsDatagramAsync(object state)
        {
            try
            {
                while (true)
                {
                    //read response datagram length
                    _tcpStream.ReadBytes(_lengthBuffer, 0, 2);
                    Array.Reverse(_lengthBuffer, 0, 2);
                    int length = BitConverter.ToUInt16(_lengthBuffer, 0);

                    //read response datagram
                    _recvBuffer.SetLength(0);
                    _tcpStream.CopyTo(_recvBuffer, 64, length);

                    _recvBuffer.Position = 0;
                    DnsDatagram response = new DnsDatagram(_recvBuffer);

                    //signal waiting thread of response
                    if (_transactions.TryGetValue(response.Identifier, out Transaction transaction))
                    {
                        transaction.Stopwatch.Stop();

                        response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, length, transaction.Stopwatch.Elapsed.TotalMilliseconds));

                        transaction.Response = response;
                        transaction.WaitHandle.Set();
                    }
                }
            }
            catch
            { }
            finally
            {
                lock (_tcpStreamLock)
                {
                    if (_tcpStream != null)
                    {
                        _tcpStream.Dispose();
                        _tcpStream = null;
                    }
                }
            }
        }

        #endregion

        #region protected

        protected virtual Stream GetNetworkStream(Socket socket)
        {
            return new NetworkStream(socket, true);
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request, int timeout)
        {
            Transaction transaction = new Transaction();

            while (!_transactions.TryAdd(request.Identifier, transaction))
                request.SetRandomIdentifier();

            try
            {
                lock (_tcpStreamLock)
                {
                    //get connection
                    Stream tcpStream = GetConnection(timeout);

                    //serialize request
                    _sendBuffer.SetLength(0);
                    request.WriteTo(_sendBuffer);

                    byte[] lengthBuffer = BitConverter.GetBytes(Convert.ToUInt16(_sendBuffer.Length));
                    Array.Reverse(lengthBuffer);

                    transaction.Stopwatch.Start();

                    //send request
                    tcpStream.Write(lengthBuffer);
                    _sendBuffer.Position = 0;
                    _sendBuffer.CopyTo(tcpStream, 32);

                    tcpStream.Flush();
                }

                //wait for response
                transaction.WaitHandle.WaitOne(timeout);
                return transaction.Response;
            }
            catch (ObjectDisposedException)
            {
                //connection is closed, return null. retry attempt will reconnect back.
                return null;
            }
            finally
            {
                _transactions.TryRemove(request.Identifier, out _);

                _lastQueried = DateTime.UtcNow;
            }
        }

        #endregion

        #region properties

        public DateTime LastQueried
        { get { return _lastQueried; } }

        #endregion

        class Transaction
        {
            public readonly EventWaitHandle WaitHandle = new ManualResetEvent(false);
            public readonly Stopwatch Stopwatch = new Stopwatch();
            public volatile DnsDatagram Response;
        }
    }
}
