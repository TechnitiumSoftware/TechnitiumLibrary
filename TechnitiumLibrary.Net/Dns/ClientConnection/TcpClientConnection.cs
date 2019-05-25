/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

        readonly Dictionary<ushort, Transaction> _transactions = new Dictionary<ushort, Transaction>();

        readonly byte[] _lengthBuffer = new byte[2];
        readonly MemoryStream _sendBuffer = new MemoryStream(32);
        readonly MemoryStream _recvBuffer = new MemoryStream(64);

        readonly object _getConnectionLock = new object();

        #endregion

        #region constructor

        public TcpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(DnsTransportProtocol.Tcp, server, proxy)
        {
            _timeout = 2000;
        }

        protected TcpClientConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
            : base(protocol, server, proxy)
        { }

        #endregion

        #region IDisposable

        bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                Stream tcpStream = _tcpStream;
                if (tcpStream != null)
                {
                    _tcpStream = null;
                    tcpStream.Dispose();
                }

                if (_sendBuffer != null)
                    _sendBuffer.Dispose();

                if (_recvBuffer != null)
                    _recvBuffer.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private Stream GetConnection()
        {
            lock (_getConnectionLock)
            {
                Stream tcpStream = _tcpStream;

                if (tcpStream != null)
                    return tcpStream;

                Socket socket;

                if (_proxy == null)
                {
                    if (_server.IPEndPoint == null)
                        _server.RecursiveResolveIPAddress();

                    socket = new Socket(_server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    IAsyncResult result = socket.BeginConnect(_server.IPEndPoint, null, null);
                    if (!result.AsyncWaitHandle.WaitOne(_timeout))
                        throw new SocketException((int)SocketError.TimedOut);

                    if (!socket.Connected)
                        throw new SocketException((int)SocketError.ConnectionRefused);
                }
                else
                {
                    socket = _proxy.Connect(_server.EndPoint, _timeout);
                }

                socket.SendTimeout = _timeout;
                socket.ReceiveTimeout = SOCKET_RECEIVE_TIMEOUT;
                socket.SendBufferSize = 512;
                socket.ReceiveBufferSize = 2048;
                socket.NoDelay = true;

                tcpStream = new WriteBufferedStream(GetNetworkStream(socket), 2048);
                _tcpStream = tcpStream;

                _readThread = new Thread(ReadDnsDatagramAsync);
                _readThread.IsBackground = true;
                _readThread.Start();

                return tcpStream;
            }
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

                    //notify waiting thread of response
                    Transaction transaction = null;

                    lock (_transactions)
                    {
                        if (_transactions.ContainsKey(response.Header.Identifier))
                            transaction = _transactions[response.Header.Identifier];
                    }

                    if (transaction != null)
                    {
                        response.SetMetadata(new DnsDatagramMetadata(_server, _protocol, length, (DateTime.UtcNow - transaction.SentAt).TotalMilliseconds));

                        lock (transaction.Lock)
                        {
                            transaction.Response = response;

                            Monitor.Pulse(transaction.Lock);
                        }
                    }
                }
            }
            catch
            { }
            finally
            {
                Stream tcpStream = _tcpStream;
                if (tcpStream != null)
                {
                    _tcpStream = null;
                    tcpStream.Dispose();
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

        public override DnsDatagram Query(DnsDatagram request)
        {
            Transaction transaction = new Transaction();

            lock (_transactions)
            {
                while (_transactions.ContainsKey(request.Header.Identifier))
                {
                    request.Header.SetRandomIdentifier();
                }

                _transactions.Add(request.Header.Identifier, transaction);
            }

            try
            {
                lock (transaction.Lock)
                {
                    Stream tcpStream = GetConnection();

                    //send request
                    lock (tcpStream)
                    {
                        //serialize request
                        _sendBuffer.SetLength(0);
                        request.WriteTo(_sendBuffer);

                        byte[] lengthBuffer = BitConverter.GetBytes(Convert.ToUInt16(_sendBuffer.Length));
                        Array.Reverse(lengthBuffer);

                        //send request
                        tcpStream.Write(lengthBuffer);
                        _sendBuffer.Position = 0;
                        _sendBuffer.CopyTo(tcpStream, 32);

                        tcpStream.Flush();
                    }

                    //wait for response
                    if (Monitor.Wait(transaction.Lock, _timeout))
                        return transaction.Response;

                    //timeout
                    return null;
                }
            }
            finally
            {
                lock (_transactions)
                {
                    _transactions.Remove(request.Header.Identifier);
                }
            }
        }

        #endregion

        class Transaction
        {
            public readonly object Lock = new object();
            public readonly DateTime SentAt = DateTime.UtcNow;
            public DnsDatagram Response;
        }
    }
}
