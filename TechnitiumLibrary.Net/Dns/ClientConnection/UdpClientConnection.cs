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
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public class UdpClientConnection : DnsClientConnection
    {
        #region variables

        const int SOCKET_POOL_SIZE = 2500;
        static int[] _socketPoolExcludedPorts;
        static PooledSocket[] _ipv4PooledSockets;
        static PooledSocket[] _ipv6PooledSockets;
        static readonly object _poolLock = new object();

        #endregion

        #region constructor

        public UdpClientConnection(NameServerAddress server, NetProxy proxy)
            : base(server, proxy)
        {
            if (server.Protocol != DnsTransportProtocol.Udp)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));
        }

        #endregion

        #region socket pool

        public static void CreateSocketPool(bool enableIPv6)
        {
            lock (_poolLock)
            {
                CreateSocketPoolIPv4();

                if (enableIPv6)
                    CreateSocketPoolIPv6();
                else
                    DisposeSocketPoolIPv6();
            }
        }

        public static void DisposeSocketPool()
        {
            lock (_poolLock)
            {
                DisposeSocketPoolIPv4();
                DisposeSocketPoolIPv6();
            }
        }

        public static void ReCreateSocketPoolIPv4()
        {
            lock (_poolLock)
            {
                if (_ipv4PooledSockets is not null)
                {
                    DisposeSocketPoolIPv4();
                    CreateSocketPoolIPv4();
                }
            }
        }

        public static void ReCreateSocketPoolIPv6()
        {
            lock (_poolLock)
            {
                if (_ipv6PooledSockets is not null)
                {
                    DisposeSocketPoolIPv6();
                    CreateSocketPoolIPv6();
                }
            }
        }

        private static void CreateSocketPoolIPv4()
        {
            if (_ipv4PooledSockets is null)
            {
                PooledSocket[] pooledSockets = new PooledSocket[SOCKET_POOL_SIZE];

                for (int i = 0; i < SOCKET_POOL_SIZE; i++)
                    pooledSockets[i] = new PooledSocket(AddressFamily.InterNetwork, i);

                _ipv4PooledSockets = pooledSockets;
            }
        }

        private static void DisposeSocketPoolIPv4()
        {
            if (_ipv4PooledSockets is not null)
            {
                foreach (PooledSocket pooledSocket in _ipv4PooledSockets)
                    pooledSocket.DisposePooled();

                _ipv4PooledSockets = null;
            }
        }

        private static void CreateSocketPoolIPv6()
        {
            if (_ipv6PooledSockets is null)
            {
                PooledSocket[] pooledSockets = new PooledSocket[SOCKET_POOL_SIZE];

                for (int i = 0; i < SOCKET_POOL_SIZE; i++)
                    pooledSockets[i] = new PooledSocket(AddressFamily.InterNetworkV6, i);

                _ipv6PooledSockets = pooledSockets;
            }
        }

        private static void DisposeSocketPoolIPv6()
        {
            if (_ipv6PooledSockets is not null)
            {
                foreach (PooledSocket pooledSocket in _ipv6PooledSockets)
                    pooledSocket.DisposePooled();

                _ipv6PooledSockets = null;
            }
        }

        private static PooledSocket GetPooledSocket(AddressFamily addressFamily)
        {
            PooledSocket[] pooledSockets;

            switch (addressFamily)
            {
                case AddressFamily.InterNetwork:
                    pooledSockets = _ipv4PooledSockets;
                    break;

                case AddressFamily.InterNetworkV6:
                    pooledSockets = _ipv6PooledSockets;
                    break;

                default:
                    throw new NotSupportedException();
            }

            if (pooledSockets is null)
                return new PooledSocket(addressFamily); //pooling not enabled; return new socket

            int j = RandomNumberGenerator.GetInt32(SOCKET_POOL_SIZE);

            for (int i = 0; i < SOCKET_POOL_SIZE; i++)
            {
                PooledSocket pooledSocket = pooledSockets[(j + i) % SOCKET_POOL_SIZE];
                if (pooledSocket.TryUse())
                    return pooledSocket; //return pooled socket
            }

            //no free pooled socket available; return new socket
            return new PooledSocket(addressFamily);
        }

        public static int[] SocketPoolExcludedPorts
        {
            get { return _socketPoolExcludedPorts; }
            set { _socketPoolExcludedPorts = value; }
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            //serialize request
            byte[] sendBuffer;
            int sendBufferSize;

            if (request.EDNS is null)
                sendBuffer = new byte[512];
            else if (request.EDNS.UdpPayloadSize > DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE)
                sendBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE];
            else
                sendBuffer = new byte[request.EDNS.UdpPayloadSize];

            try
            {
                using (MemoryStream mS = new MemoryStream(sendBuffer))
                {
                    request.WriteTo(mS);
                    sendBufferSize = (int)mS.Position;
                }
            }
            catch (NotSupportedException)
            {
                throw new DnsClientException("DnsClient cannot send the request: request exceeds the UDP payload size limit of " + sendBuffer.Length + " bytes.");
            }

            byte[] receiveBuffer = new byte[sendBuffer.Length];
            Stopwatch stopwatch = new Stopwatch();
            DnsDatagram lastResponse = null;
            Exception lastException = null;

            bool IsResponseValid(int receivedBytes)
            {
                try
                {
                    //parse response
                    using (MemoryStream mS = new MemoryStream(receiveBuffer, 0, receivedBytes))
                    {
                        DnsDatagram response = DnsDatagram.ReadFrom(mS);
                        response.SetMetadata(_server, stopwatch.Elapsed.TotalMilliseconds);

                        ValidateResponse(request, response);

                        lastResponse = response;
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    return false;
                }
            }

            if (_proxy is null)
            {
                if (_server.IsIPEndPointStale)
                    await _server.RecursiveResolveIPAddressAsync(cancellationToken: cancellationToken);

                using (PooledSocket pooledSocket = GetPooledSocket(_server.IPEndPoint.AddressFamily))
                {
                    stopwatch.Start();

                    try
                    {
                        _ = await pooledSocket.Socket.UdpQueryAsync(new ArraySegment<byte>(sendBuffer, 0, sendBufferSize), receiveBuffer, _server.IPEndPoint, timeout, retries, false, IsResponseValid, cancellationToken);
                    }
                    catch (SocketException ex)
                    {
                        if (ex.SocketErrorCode == SocketError.TimedOut)
                        {
                            if (lastException is not null)
                                ExceptionDispatchInfo.Throw(lastException);

                            throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out.", ex);
                        }

                        throw;
                    }

                    stopwatch.Stop();
                }
            }
            else
            {
                stopwatch.Start();

                try
                {
                    _ = await _proxy.UdpQueryAsync(new ArraySegment<byte>(sendBuffer, 0, sendBufferSize), receiveBuffer, _server.EndPoint, timeout, retries, false, IsResponseValid, cancellationToken);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        if (lastException is not null)
                            ExceptionDispatchInfo.Throw(lastException);

                        throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out.", ex);
                    }

                    throw;
                }

                stopwatch.Stop();
            }

            if (lastResponse is not null)
                return lastResponse;

            if (lastException is not null)
                ExceptionDispatchInfo.Throw(lastException);

            throw new InvalidOperationException();
        }

        #endregion

        class PooledSocket : IDisposable
        {
            #region variables

            readonly static IPEndPoint _ipv4Any = new IPEndPoint(IPAddress.Any, 0);
            readonly static IPEndPoint _ipv6Any = new IPEndPoint(IPAddress.IPv6Any, 0);

            readonly Socket _socket;
            readonly int _index;

            volatile int _inUse;

            #endregion

            #region constructor

            public PooledSocket(AddressFamily addressFamily, int index = -1)
            {
                _socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
                _index = index;

                switch (addressFamily)
                {
                    case AddressFamily.InterNetwork:
                        {
                            if (index < 0)
                            {
                                if (_ipv4BindEP is null)
                                {
                                    _socket.Bind(_ipv4Any);
                                }
                                else
                                {
                                    if (_ipv4BindToInterfaceName is not null)
                                        _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, _ipv4BindToInterfaceName);

                                    _socket.Bind(_ipv4BindEP);
                                }
                            }
                            else
                            {
                                if (_ipv4BindEP is null)
                                {
                                    try
                                    {
                                        _socket.Bind(new IPEndPoint(IPAddress.Any, GetRandomPort()));
                                    }
                                    catch (SocketException)
                                    {
                                        _socket.Bind(_ipv4Any);
                                    }
                                }
                                else
                                {
                                    if (_ipv4BindToInterfaceName is not null)
                                        _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, _ipv4BindToInterfaceName);

                                    try
                                    {
                                        _socket.Bind(new IPEndPoint(_ipv4BindEP.Address, GetRandomPort()));
                                    }
                                    catch (SocketException)
                                    {
                                        _socket.Bind(_ipv4BindEP);
                                    }
                                }
                            }
                        }
                        break;

                    case AddressFamily.InterNetworkV6:
                        {
                            if (index < 0)
                            {
                                if (_ipv6BindEP is null)
                                {
                                    _socket.Bind(_ipv6Any);
                                }
                                else
                                {
                                    if (_ipv6BindToInterfaceName is not null)
                                        _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, _ipv6BindToInterfaceName);

                                    _socket.Bind(_ipv6BindEP);
                                }
                            }
                            else
                            {
                                if (_ipv6BindEP is null)
                                {
                                    try
                                    {
                                        _socket.Bind(new IPEndPoint(IPAddress.IPv6Any, GetRandomPort()));
                                    }
                                    catch (SocketException)
                                    {
                                        _socket.Bind(_ipv6Any);
                                    }
                                }
                                else
                                {
                                    if (_ipv6BindToInterfaceName is not null)
                                        _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, _ipv6BindToInterfaceName);

                                    try
                                    {
                                        _socket.Bind(new IPEndPoint(_ipv6BindEP.Address, GetRandomPort()));
                                    }
                                    catch (SocketException)
                                    {
                                        _socket.Bind(_ipv6BindEP);
                                    }
                                }
                            }
                        }
                        break;
                }
            }

            #endregion

            #region IDisposable

            public void Dispose()
            {
                if (_index < 0)
                    _socket.Dispose(); //dispose non-pooled socket
                else
                    _inUse = 0; //free pooled socket
            }

            #endregion

            #region private

            private static int GetRandomPort()
            {
                int port = RandomNumberGenerator.GetInt32(1000, ushort.MaxValue);

                if (_socketPoolExcludedPorts is not null)
                {
                    foreach (int excludedPort in _socketPoolExcludedPorts)
                    {
                        if (port == excludedPort)
                            return 0;
                    }
                }

                return port;
            }

            #endregion

            #region public

            public bool TryUse()
            {
                return Interlocked.CompareExchange(ref _inUse, 1, 0) == 0;
            }

            public void DisposePooled()
            {
                _inUse = 1; //to make TryUse() return false and thus prevent use
                _socket.Dispose();
            }

            #endregion

            #region properties

            public Socket Socket
            { get { return _socket; } }

            #endregion
        }
    }
}
