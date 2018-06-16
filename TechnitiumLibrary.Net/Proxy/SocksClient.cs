/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    enum SocksMethod : byte
    {
        NoAuthenticationRequired = 0x0,
        GSSAPI = 0x01,
        UsernamePassword = 0x2,
        NoAcceptableMethods = 0xff
    }

    enum SocksRequestCommand : byte
    {
        Connect = 0x01,
        Bind = 0x02,
        UdpAssociate = 0x03
    }

    enum SocksReplyCode : byte
    {
        Succeeded = 0x00,
        GeneralSocksServerFailure = 0x01,
        ConnectionNotAllowedByRuleset = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TtlExpired = 0x06,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08
    }

    public enum SocksAddressType : byte
    {
        IPv4Address = 0x01,
        DomainName = 0x03,
        IPv6Address = 0x04
    }

    public class SocksClient
    {
        #region variables

        public const byte SOCKS_VERSION = 5;

        EndPoint _proxyEP;
        NetworkCredential _credential;

        byte[] _negotiationRequest;
        byte[] _authRequest;

        #endregion

        #region constructor

        public SocksClient(string proxyAddress, int port = 1080, NetworkCredential credential = null)
        {
            _proxyEP = new DomainEndPoint(proxyAddress, port);

            Init(credential);
        }

        public SocksClient(IPAddress proxyAddress, int port = 1080, NetworkCredential credential = null)
        {
            _proxyEP = new IPEndPoint(proxyAddress, port);

            Init(credential);
        }

        public SocksClient(EndPoint proxyEndPoint, NetworkCredential credential = null)
        {
            _proxyEP = proxyEndPoint;

            Init(credential);
        }

        #endregion

        #region private

        private void Init(NetworkCredential credential)
        {
            _credential = credential;

            if (_credential == null)
            {
                _negotiationRequest = new byte[3];

                _negotiationRequest[0] = SOCKS_VERSION;
                _negotiationRequest[1] = 1; //total methods
                _negotiationRequest[2] = (byte)SocksMethod.NoAuthenticationRequired;
            }
            else
            {
                _negotiationRequest = new byte[4];

                _negotiationRequest[0] = SOCKS_VERSION;
                _negotiationRequest[1] = 2; //total methods
                _negotiationRequest[2] = (byte)SocksMethod.NoAuthenticationRequired;
                _negotiationRequest[3] = (byte)SocksMethod.UsernamePassword;

                _authRequest = new byte[1 + 1 + _credential.UserName.Length + 1 + _credential.Password.Length];

                _authRequest[0] = 0x01;
                _authRequest[1] = Convert.ToByte(_credential.UserName.Length);
                Buffer.BlockCopy(Encoding.ASCII.GetBytes(_credential.UserName), 0, _authRequest, 2, _credential.UserName.Length);
                _authRequest[2 + _credential.UserName.Length] = Convert.ToByte(_credential.Password.Length);
                Buffer.BlockCopy(Encoding.ASCII.GetBytes(_credential.Password), 0, _authRequest, 2 + _credential.UserName.Length + 1, _credential.Password.Length);
            }
        }

        private void Negotiate(Socket socket)
        {
            byte[] response = new byte[2];

            socket.Send(_negotiationRequest);
            if (socket.Receive(response) != 2)
                throw new SocksClientException("The connection was reset by the remote peer.");

            if (response[0] != SOCKS_VERSION)
                throw new SocksClientException("Socks version 5 is not supported by the proxy server.");

            switch ((SocksMethod)response[1])
            {
                case SocksMethod.UsernamePassword:
                    if (_authRequest == null)
                        throw new SocksClientException("Socks proxy server requires authentication.");

                    socket.Send(_authRequest);
                    if (socket.Receive(response) != 2)
                        throw new SocksClientException("The connection was reset by the remote peer.");

                    if (response[0] != 0x01)
                        throw new SocksClientException("Socks proxy server does not support username/password method version 1.");

                    if (response[1] != 0x00)
                        throw new SocksClientException("Socks proxy server authentication failed: invalid username or password.");

                    break;

                case SocksMethod.NoAuthenticationRequired:
                    break;

                case SocksMethod.NoAcceptableMethods:
                    if (_authRequest == null)
                        throw new SocksClientException("Socks proxy server requires authentication.");
                    else
                        throw new SocksClientException("Socks proxy server does not support username/password method.");

                default:
                    throw new SocksClientException("Socks proxy server returned unknown method.");
            }
        }

        private static EndPoint Request(Socket socket, SocksRequestCommand command, EndPoint dstAddr)
        {
            socket.Send(CreateRequest(command, dstAddr));

            byte[] response = new byte[262];

            if (socket.Receive(response) < 10)
                throw new SocksClientException("The connection was reset by the remote peer.");

            if (response[0] != SOCKS_VERSION)
                throw new SocksClientException("Socks version 5 is not supported by the proxy server.");

            SocksReplyCode reply = (SocksReplyCode)response[1];

            if (reply != SocksReplyCode.Succeeded)
                throw new SocksClientException("Socks proxy server request failed: " + reply.ToString());

            return ParseEndpoint(response, 3);
        }

        internal static EndPoint ParseEndpoint(byte[] buffer, int offset)
        {
            switch ((SocksAddressType)buffer[offset])
            {
                case SocksAddressType.IPv4Address:
                    {
                        byte[] address = new byte[4];
                        Buffer.BlockCopy(buffer, offset + 1, address, 0, 4);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 4, port, 0, 2);
                        Array.Reverse(port);

                        return new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }

                case SocksAddressType.IPv6Address:
                    {
                        byte[] address = new byte[16];
                        Buffer.BlockCopy(buffer, offset + 1, address, 0, 16);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 16, port, 0, 2);
                        Array.Reverse(port);

                        return new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }

                case SocksAddressType.DomainName:
                    {
                        int length = buffer[offset + 1];

                        byte[] address = new byte[length];
                        Buffer.BlockCopy(buffer, offset + 1 + 1, address, 0, length);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 1 + length, port, 0, 2);
                        Array.Reverse(port);

                        return new DomainEndPoint(Encoding.ASCII.GetString(address), BitConverter.ToUInt16(port, 0));
                    }

                default:
                    throw new NotSupportedException("SocksAddressType not supported.");
            }
        }

        private static byte[] CreateRequest(SocksRequestCommand command, EndPoint dstAddr)
        {
            //get type, address bytes & port bytes
            SocksAddressType type;
            byte[] address;
            ushort port;

            switch (dstAddr.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        type = SocksAddressType.IPv4Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        type = SocksAddressType.IPv6Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.Unspecified:
                    {
                        type = SocksAddressType.DomainName;

                        DomainEndPoint ep = dstAddr as DomainEndPoint;
                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            //create request
            byte[] request = new byte[address.Length + 6];

            request[0] = SocksClient.SOCKS_VERSION;
            request[1] = (byte)command;
            request[3] = (byte)type;

            Buffer.BlockCopy(address, 0, request, 4, address.Length);

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);
            Buffer.BlockCopy(portBytes, 0, request, 4 + address.Length, 2);

            return request;
        }

        private Socket GetProxyConnection(int timeout)
        {
            Socket socket;
            IAsyncResult result;

            switch (_proxyEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    result = socket.BeginConnect(_proxyEP, null, null);
                    break;

                case AddressFamily.InterNetworkV6:
                    socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    result = socket.BeginConnect(_proxyEP, null, null);
                    break;

                case AddressFamily.Unspecified:
                    switch (Environment.OSVersion.Platform)
                    {
                        case PlatformID.Win32NT:
                            if (Environment.OSVersion.Version.Major < 6)
                            {
                                //below vista
                                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                            }
                            else
                            {
                                //vista & above
                                socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                            }
                            break;

                        case PlatformID.Unix:
                            if (Socket.OSSupportsIPv6)
                                socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                            else
                                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                            break;

                        default: //unknown
                            socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                            break;
                    }

                    DomainEndPoint ep = _proxyEP as DomainEndPoint;
                    result = socket.BeginConnect(ep.Address, ep.Port, null, null);
                    break;

                default:
                    throw new SocksClientException("Invalid socks address type.");
            }

            if (!result.AsyncWaitHandle.WaitOne(timeout))
                throw new SocketException((int)SocketError.TimedOut);

            if (!socket.Connected)
                throw new SocketException((int)SocketError.ConnectionRefused);

            socket.NoDelay = true;

            return socket;
        }

        #endregion

        #region public

        public bool IsProxyAvailable()
        {
            try
            {
                //connect to proxy server
                using (Socket socket = GetProxyConnection(5000))
                {
                    socket.SendTimeout = 5000;
                    socket.ReceiveTimeout = 5000;

                    Negotiate(socket);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void CheckProxyAccess()
        {
            //connect to proxy server
            using (Socket socket = GetProxyConnection(5000))
            {
                socket.SendTimeout = 5000;
                socket.ReceiveTimeout = 5000;

                Negotiate(socket);
            }
        }

        public SocksConnectRequestHandler Connect(IPAddress address, int port, int timeout = 10000)
        {
            return Connect(new IPEndPoint(address, port), timeout);
        }

        public SocksConnectRequestHandler Connect(string address, int port, int timeout = 10000)
        {
            return Connect(new DomainEndPoint(address, port), timeout);
        }

        public SocksConnectRequestHandler Connect(EndPoint remoteEP, int timeout = 10000)
        {
            //connect to proxy server
            Socket socket = GetProxyConnection(timeout);

            socket.SendTimeout = 30000;
            socket.ReceiveTimeout = 30000;

            try
            {
                Negotiate(socket);
                EndPoint bindEP = Request(socket, SocksRequestCommand.Connect, remoteEP);

                return new SocksConnectRequestHandler(socket, remoteEP, bindEP);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public SocksBindRequestHandler Bind(EndPoint endpoint, int timeout = 10000)
        {
            //connect to proxy server
            Socket socket = GetProxyConnection(timeout);

            socket.SendTimeout = 30000;
            socket.ReceiveTimeout = 30000;

            try
            {
                Negotiate(socket);
                EndPoint bindEP = Request(socket, SocksRequestCommand.Bind, endpoint);

                return new SocksBindRequestHandler(socket, bindEP);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(int timeout = 10000)
        {
            return UdpAssociate(new IPEndPoint(IPAddress.Any, 0), timeout);
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(int localPort, int timeout = 10000)
        {
            return UdpAssociate(new IPEndPoint(IPAddress.Any, localPort), timeout);
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(IPEndPoint localEP, int timeout = 10000)
        {
            //bind local ep
            Socket udpSocket = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(localEP);

            //connect to proxy server
            Socket socket = GetProxyConnection(timeout);

            socket.SendTimeout = 30000;
            socket.ReceiveTimeout = 30000;

            try
            {
                Negotiate(socket);

                EndPoint relayEP = Request(socket, SocksRequestCommand.UdpAssociate, udpSocket.LocalEndPoint);

                return new SocksUdpAssociateRequestHandler(socket, udpSocket, relayEP);
            }
            catch
            {
                if (socket != null)
                    socket.Dispose();

                if (udpSocket != null)
                    udpSocket.Dispose();

                throw;
            }
        }

        #endregion

        #region properties

        public EndPoint ProxyEndPoint
        {
            get { return _proxyEP; }
            set { _proxyEP = value; }
        }

        public NetworkCredential Credential
        {
            get { return _credential; }
            set
            {
                Init(value);

                _credential = value;
            }
        }

        #endregion
    }

    public class SocksConnectRequestHandler : IDisposable
    {
        #region variables

        Socket _socket;
        EndPoint _dstEP;
        EndPoint _bindEP;

        bool _emulateHttpProxy;
        Socket _tunnelSocketListener;
        Timer _timeoutTimer;
        Joint _tunnelJoint;

        #endregion

        #region constructor

        internal SocksConnectRequestHandler(Socket socket, EndPoint dstEP, EndPoint bindEP)
        {
            _socket = socket;
            _dstEP = dstEP;
            _bindEP = bindEP;
        }

        #endregion

        #region IDisposable

        ~SocksConnectRequestHandler()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_socket != null)
                {
                    if (disposing)
                        _socket.Shutdown(SocketShutdown.Both);

                    _socket.Dispose();
                }

                if (_tunnelSocketListener != null)
                    _tunnelSocketListener.Dispose();

                if (_timeoutTimer != null)
                    _timeoutTimer.Dispose();

                if (_tunnelJoint != null)
                    _tunnelJoint.Dispose();

                _disposed = true;
            }
        }

        #endregion

        #region private

        private void AcceptTunnelConnectionAsync(object state)
        {
            try
            {
                _timeoutTimer = new Timer(TimeoutTimerAsync, null, 30000, Timeout.Infinite);

                Socket tunnelSocket = _tunnelSocketListener.Accept();

                tunnelSocket.NoDelay = true;

                _timeoutTimer.Dispose();
                _timeoutTimer = null;

                _tunnelSocketListener.Dispose();
                _tunnelSocketListener = null;

                if (_emulateHttpProxy)
                {
                    byte[] proxyRequest = new byte[128];
                    byte[] proxyResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");

                    do
                    {
                        tunnelSocket.Receive(proxyRequest);
                    }
                    while (tunnelSocket.Available > 0);

                    tunnelSocket.Send(proxyResponse);
                }

                _tunnelJoint = new Joint(new NetworkStream(_socket), new NetworkStream(tunnelSocket));
                _tunnelJoint.Start();
            }
            catch
            {
                this.Dispose();
            }
        }

        private void TimeoutTimerAsync(object state)
        {
            try
            {
                if (_tunnelSocketListener != null)
                    this.Dispose();
            }
            catch
            { }
        }

        #endregion

        #region public

        public IPEndPoint CreateLocalTunnel()
        {
            _tunnelSocketListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _tunnelSocketListener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _tunnelSocketListener.Listen(1);

            ThreadPool.QueueUserWorkItem(AcceptTunnelConnectionAsync);

            return (IPEndPoint)_tunnelSocketListener.LocalEndPoint;
        }

        public WebProxy CreateLocalHttpProxyConnectTunnel()
        {
            IPEndPoint proxyEP = CreateLocalTunnel();
            _emulateHttpProxy = true;

            return new WebProxy(proxyEP.Address.ToString(), proxyEP.Port);
        }

        public Socket GetSocket()
        {
            Socket socket = _socket;
            _socket = null;

            return socket;
        }

        #endregion

        #region properties

        public EndPoint ProxyRemoteEndPoint
        { get { return _dstEP; } }

        public EndPoint ProxyLocalEndPoint
        { get { return _bindEP; } }

        #endregion
    }

    public class SocksBindRequestHandler : IDisposable
    {
        #region variables

        Socket _socket;
        EndPoint _bindEP;

        EndPoint _dstEP;

        #endregion

        #region constructor

        internal SocksBindRequestHandler(Socket socket, EndPoint bindEP)
        {
            _socket = socket;
            _bindEP = bindEP;
        }

        #endregion

        #region IDisposable

        ~SocksBindRequestHandler()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                    _socket.Shutdown(SocketShutdown.Both);

                _socket.Dispose();

                _disposed = true;
            }
        }

        #endregion

        #region public

        public Socket Accept()
        {
            byte[] response = new byte[262];

            if (_socket.Receive(response) < 10)
                throw new SocksClientException("The connection was reset by the remote peer.");

            if (response[0] != SocksClient.SOCKS_VERSION)
                throw new SocksClientException("Socks version 5 is not supported by the proxy server.");

            SocksReplyCode reply = (SocksReplyCode)response[1];

            if (reply != SocksReplyCode.Succeeded)
                throw new SocksClientException("Socks proxy server request failed: " + reply.ToString());

            _dstEP = SocksClient.ParseEndpoint(response, 3);

            return _socket;
        }

        #endregion

        #region properties

        public EndPoint ProxyRemoteEndPoint
        { get { return _dstEP; } }

        public EndPoint ProxyLocalEndPoint
        { get { return _bindEP; } }

        #endregion
    }

    public class SocksUdpAssociateRequestHandler : IDisposable
    {
        #region variables

        Socket _controlSocket;
        Socket _udpSocket;
        EndPoint _relayEP;

        Thread _watchThread;

        #endregion

        #region constructor

        internal SocksUdpAssociateRequestHandler(Socket controlSocket, Socket udpSocket, EndPoint relayEP)
        {
            _controlSocket = controlSocket;
            _udpSocket = udpSocket;
            _relayEP = relayEP;

            _watchThread = new Thread(ControlSocketWatchAsync);
            _watchThread.IsBackground = true;
            _watchThread.Start();
        }

        #endregion

        #region IDisposable

        ~SocksUdpAssociateRequestHandler()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_watchThread != null)
                    _watchThread.Abort();

                if (disposing)
                {
                    _controlSocket.Shutdown(SocketShutdown.Both);
                    _udpSocket.Shutdown(SocketShutdown.Both);
                }

                _controlSocket.Dispose();
                _udpSocket.Dispose();

                _disposed = true;
            }
        }

        #endregion

        #region private

        private static byte[] CreateUdpDatagram(byte[] buffer, int offset, int size, EndPoint dstAddr)
        {
            //get type, address bytes & port bytes
            SocksAddressType type;
            byte[] address;
            ushort port;

            switch (dstAddr.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        type = SocksAddressType.IPv4Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        type = SocksAddressType.IPv6Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.Unspecified:
                    {
                        type = SocksAddressType.DomainName;

                        DomainEndPoint ep = dstAddr as DomainEndPoint;
                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            //create datagram
            byte[] datagram = new byte[address.Length + 6 + size];

            datagram[2] = 0x00;
            datagram[3] = (byte)type;

            Buffer.BlockCopy(address, 0, datagram, 4, address.Length);

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);
            Buffer.BlockCopy(portBytes, 0, datagram, 4 + address.Length, 2);

            Buffer.BlockCopy(buffer, offset, datagram, 4 + address.Length + 2, size);

            return datagram;
        }

        private void ControlSocketWatchAsync(object state)
        {
            try
            {
                byte[] buffer = new byte[128];

                while (true)
                {
                    int bytesRecv = _controlSocket.Receive(buffer);

                    if (bytesRecv < 1)
                    {
                        _watchThread = null;
                        this.Dispose();
                        break;
                    }
                }
            }
            catch (ObjectDisposedException)
            { }
            catch (ThreadAbortException)
            { }
            catch
            {
                this.Dispose();
            }
        }

        #endregion

        #region public

        public void SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP)
        {
            byte[] datagram = CreateUdpDatagram(buffer, offset, size, remoteEP);

            _udpSocket.SendTo(datagram, _relayEP);
        }

        public int ReceiveFrom(byte[] buffer, int offset, int size, out EndPoint remoteEP)
        {
            byte[] datagram = new byte[262 + size];
            EndPoint dummyEP = new IPEndPoint(IPAddress.Any, 0);

            int bytesReceived = _udpSocket.ReceiveFrom(datagram, 0, datagram.Length, SocketFlags.None, ref dummyEP);

            if (bytesReceived < 10)
                throw new SocksClientException("The connection was reset by the remote peer.");

            remoteEP = SocksClient.ParseEndpoint(datagram, 3);

            int addressSize;

            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    addressSize = 4;
                    break;

                case AddressFamily.InterNetworkV6:
                    addressSize = 16;
                    break;

                case AddressFamily.Unspecified:
                    addressSize = 1 + (remoteEP as DomainEndPoint).Address.Length;
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            int dataOffset = 6 + addressSize;
            int dataSize = bytesReceived - dataOffset;

            if (dataSize > size)
                dataSize = size;

            Buffer.BlockCopy(datagram, dataOffset, buffer, offset, dataSize);

            return dataSize;
        }

        #endregion

        #region properties

        public bool ProxyConnected
        { get { return _controlSocket.Connected; } }

        public EndPoint ProxyUdpRelayEndPoint
        { get { return _relayEP; } }

        public int ReceiveTimeout
        {
            get { return _udpSocket.ReceiveTimeout; }
            set { _udpSocket.ReceiveTimeout = value; }
        }

        #endregion
    }

    public class SocksClientException : Exception
    {
        #region constructors

        public SocksClientException()
            : base()
        { }

        public SocksClientException(string message)
            : base(message)
        { }

        public SocksClientException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected SocksClientException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}
