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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public enum SocksAddressType : byte
    {
        IPv4Address = 0x01,
        DomainName = 0x03,
        IPv6Address = 0x04
    }

    public class SocksProxyServer : IDisposable
    {
        #region variables

        const int CLIENT_WAIT_TIMEOUT = 30000;

        readonly IPEndPoint _localEP;
        readonly IProxyServerConnectionManager _connectionManager;
        readonly IProxyServerAuthenticationManager _authenticationManager;

        readonly Socket _listener;
        readonly ConcurrentDictionary<ProxyServerSession, object> _sessions = new ConcurrentDictionary<ProxyServerSession, object>();

        #endregion

        #region constructors

        public SocksProxyServer(IProxyServerConnectionManager connectionManager = null, IProxyServerAuthenticationManager authenticationManager = null, int backlog = 10)
            : this(new IPEndPoint(IPAddress.Loopback, 0), connectionManager, authenticationManager, backlog)
        { }

        public SocksProxyServer(IPEndPoint localEP, IProxyServerConnectionManager connectionManager = null, IProxyServerAuthenticationManager authenticationManager = null, int backlog = 10)
        {
            _listener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(localEP);
            _listener.Listen(backlog);

            _localEP = (IPEndPoint)_listener.LocalEndPoint;
            _connectionManager = connectionManager;
            _authenticationManager = authenticationManager;

            if (_connectionManager == null)
                _connectionManager = new DefaultProxyServerConnectionManager();

            //accept requests async
            _ = Task.Factory.StartNew(AcceptRequestAsync, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_listener != null)
                    _listener.Dispose();

                foreach (ProxyServerSession session in _sessions.Keys)
                    session.Dispose();

                _sessions.Clear();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private async Task AcceptRequestAsync()
        {
            try
            {
                while (true)
                {
                    Socket socket = await _listener.AcceptAsync();

                    ProxyServerSession session = new ProxyServerSession(socket, _connectionManager, _authenticationManager);

                    session.Disposed += delegate (object sender, EventArgs e)
                    {
                        _sessions.TryRemove(sender as ProxyServerSession, out _);
                    };

                    if (_sessions.TryAdd(session, null))
                        _ = Task.Factory.StartNew(session.StartAsync, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
                }
            }
            finally
            {
                Dispose();
            }
        }

        #endregion

        #region static

        internal static async Task<EndPoint> ReadEndPointAsync(Stream s)
        {
            byte[] buffer = new byte[2];

            await s.ReadBytesAsync(buffer, 0, 1);
            SocksAddressType addressType = (SocksAddressType)buffer[0];

            switch (addressType)
            {
                case SocksAddressType.IPv4Address:
                    {
                        byte[] addressBytes = new byte[4];
                        await s.ReadBytesAsync(addressBytes, 0, 4);
                        await s.ReadBytesAsync(buffer, 0, 2);
                        Array.Reverse(buffer, 0, 2);

                        return new IPEndPoint(new IPAddress(addressBytes), BitConverter.ToUInt16(buffer, 0));
                    }

                case SocksAddressType.IPv6Address:
                    {
                        byte[] addressBytes = new byte[16];
                        await s.ReadBytesAsync(addressBytes, 0, 16);
                        await s.ReadBytesAsync(buffer, 0, 2);
                        Array.Reverse(buffer, 0, 2);

                        return new IPEndPoint(new IPAddress(addressBytes), BitConverter.ToUInt16(buffer, 0));
                    }

                case SocksAddressType.DomainName:
                    {
                        await s.ReadBytesAsync(buffer, 0, 1);
                        byte[] addressBytes = new byte[buffer[0]];
                        await s.ReadBytesAsync(addressBytes, 0, addressBytes.Length);
                        string domain = Encoding.ASCII.GetString(addressBytes);

                        await s.ReadBytesAsync(buffer, 0, 2);
                        Array.Reverse(buffer, 0, 2);

                        return new DomainEndPoint(domain, BitConverter.ToUInt16(buffer, 0));
                    }

                default:
                    return null;
            }
        }

        internal static async Task WriteEndPointAsync(EndPoint endPoint, Stream s)
        {
            SocksAddressType addressType;
            byte[] address;
            ushort port;

            switch (endPoint.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        addressType = SocksAddressType.IPv4Address;

                        IPEndPoint ep = endPoint as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        addressType = SocksAddressType.IPv6Address;

                        IPEndPoint ep = endPoint as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.Unspecified:
                    {
                        addressType = SocksAddressType.DomainName;

                        DomainEndPoint ep = endPoint as DomainEndPoint;
                        if (ep == null)
                            throw new NotSupportedException("AddressFamily not supported.");

                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);

            await s.WriteAsync(new byte[] { (byte)addressType });
            await s.WriteAsync(address, 0, address.Length);
            await s.WriteAsync(portBytes, 0, 2);
        }

        #endregion

        #region properties

        public IPEndPoint LocalEndPoint
        { get { return _localEP; } }

        #endregion

        class ProxyServerSession : IDisposable
        {
            #region events

            public event EventHandler Disposed;

            #endregion

            #region variables

            readonly Socket _localSocket;
            readonly IProxyServerConnectionManager _connectionManager;
            readonly IProxyServerAuthenticationManager _authenticationManager;

            Socket _udpRelaySocket;
            Socket _remoteSocket;

            #endregion

            #region constructor

            public ProxyServerSession(Socket localSocket, IProxyServerConnectionManager connectionManager, IProxyServerAuthenticationManager authenticationManager)
            {
                _localSocket = localSocket;
                _connectionManager = connectionManager;
                _authenticationManager = authenticationManager;
            }

            #endregion

            #region IDisposable

            bool _disposed;
            readonly object _disposeLock = new object();

            public void Dispose()
            {
                Dispose(true);
            }

            protected virtual void Dispose(bool disposing)
            {
                lock (_disposeLock)
                {
                    if (_disposed)
                        return;

                    if (disposing)
                    {
                        if (_localSocket != null)
                            _localSocket.Dispose();

                        if (_udpRelaySocket != null)
                            _udpRelaySocket.Dispose();

                        if (_remoteSocket != null)
                            _remoteSocket.Dispose();
                    }

                    _disposed = true;
                    Disposed?.Invoke(this, EventArgs.Empty);
                }
            }

            #endregion

            #region private

            private async Task CopyToAsync(Socket src, SocksProxyUdpAssociateHandler dst)
            {
                try
                {
                    byte[] buffer = new byte[64 * 1024];

                    while (true)
                    {
                        UdpReceiveFromResult result = await src.ReceiveFromAsync(buffer);
                        await dst.SendToAsync(buffer, 0, result.BytesReceived, result.RemoteEndPoint);
                    }
                }
                finally
                {
                    Dispose();
                }
            }

            #endregion

            #region public

            public async Task StartAsync()
            {
                bool dontDispose = false;

                try
                {
                    NetworkStream localNetworkStream = new NetworkStream(_localSocket);
                    Stream localStream = new WriteBufferedStream(localNetworkStream, 512);

                    #region authenticate

                    SocksProxyNegotiationRequest negotiationRequest = await SocksProxyNegotiationRequest.ReadRequestAsync(localStream).WithTimeout(CLIENT_WAIT_TIMEOUT);
                    if (!negotiationRequest.IsVersionSupported)
                    {
                        await new SocksProxyNegotiationReply(SocksProxyAuthenticationMethod.NoAcceptableMethods).WriteToAsync(localStream);
                        await localStream.FlushAsync();
                        return;
                    }

                    //match method and authenticate
                    bool methodMatched = false;
                    SocksProxyAuthenticationMethod serverMethod = _authenticationManager == null ? SocksProxyAuthenticationMethod.NoAuthenticationRequired : SocksProxyAuthenticationMethod.UsernamePassword;

                    foreach (SocksProxyAuthenticationMethod method in negotiationRequest.Methods)
                    {
                        if (method == serverMethod)
                        {
                            //method matches
                            await new SocksProxyNegotiationReply(method).WriteToAsync(localStream);
                            await localStream.FlushAsync();

                            switch (serverMethod)
                            {
                                case SocksProxyAuthenticationMethod.NoAuthenticationRequired:
                                    methodMatched = true;
                                    break;

                                case SocksProxyAuthenticationMethod.UsernamePassword:
                                    //read method version

                                    SocksProxyAuthenticationRequest authenticationRequest = await SocksProxyAuthenticationRequest.ReadRequestAsync(localStream).WithTimeout(CLIENT_WAIT_TIMEOUT);
                                    if (!authenticationRequest.IsVersionSupported)
                                    {
                                        await new SocksProxyAuthenticationReply(SocksProxyAuthenticationStatus.Failure).WriteToAsync(localStream);
                                        await localStream.FlushAsync();
                                        return;
                                    }

                                    if (!_authenticationManager.Authenticate(authenticationRequest.Username, authenticationRequest.Password))
                                    {
                                        await new SocksProxyAuthenticationReply(SocksProxyAuthenticationStatus.Failure).WriteToAsync(localStream);
                                        await localStream.FlushAsync();
                                        return;
                                    }

                                    await new SocksProxyAuthenticationReply(SocksProxyAuthenticationStatus.Success).WriteToAsync(localStream);
                                    await localStream.FlushAsync();
                                    methodMatched = true;
                                    break;
                            }

                            break;
                        }
                    }

                    if (!methodMatched)
                    {
                        //no method matched
                        await new SocksProxyNegotiationReply(SocksProxyAuthenticationMethod.NoAcceptableMethods).WriteToAsync(localStream);
                        await localStream.FlushAsync();
                        return;
                    }

                    #endregion

                    #region process request

                    //read request
                    SocksProxyRequest request = await SocksProxyRequest.ReadRequestAsync(localStream).WithTimeout(CLIENT_WAIT_TIMEOUT);
                    if (!request.IsVersionSupported)
                    {
                        await new SocksProxyReply(SocksProxyReplyCode.GeneralSocksServerFailure).WriteToAsync(localStream);
                        await localStream.FlushAsync();
                        return;
                    }

                    //process command
                    SocksProxyReplyCode reply;
                    EndPoint bindEP;

                    switch (request.Command)
                    {
                        case SocksProxyRequestCommand.Connect:
                            {
                                try
                                {
                                    _remoteSocket = await _connectionManager.ConnectAsync(request.DestinationEndPoint);
                                    reply = SocksProxyReplyCode.Succeeded;
                                    bindEP = _remoteSocket.LocalEndPoint;
                                }
                                catch (SocketException ex)
                                {
                                    switch (ex.SocketErrorCode)
                                    {
                                        case SocketError.NetworkUnreachable:
                                            reply = SocksProxyReplyCode.NetworkUnreachable;
                                            break;

                                        case SocketError.HostUnreachable:
                                            reply = SocksProxyReplyCode.HostUnreachable;
                                            break;

                                        case SocketError.ConnectionRefused:
                                            reply = SocksProxyReplyCode.ConnectionRefused;
                                            break;

                                        default:
                                            reply = SocksProxyReplyCode.GeneralSocksServerFailure;
                                            break;
                                    }

                                    bindEP = new IPEndPoint(IPAddress.Any, 0);
                                }
                            }
                            break;

                        case SocksProxyRequestCommand.Bind:
                            {
                                EndPoint endPoint = null;
                                NetworkInfo networkInfo = null;

                                switch (request.DestinationEndPoint.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                        endPoint = new IPEndPoint(IPAddress.Any, 0);
                                        networkInfo = NetUtilities.GetDefaultIPv4NetworkInfo();
                                        break;

                                    case AddressFamily.InterNetworkV6:
                                        endPoint = new IPEndPoint(IPAddress.Any, 0);
                                        networkInfo = NetUtilities.GetDefaultIPv6NetworkInfo();
                                        break;

                                    default:
                                        break;
                                }

                                if (endPoint == null)
                                {
                                    reply = SocksProxyReplyCode.AddressTypeNotSupported;
                                    bindEP = new IPEndPoint(IPAddress.Any, 0);
                                }
                                else
                                {
                                    if (networkInfo == null)
                                    {
                                        reply = SocksProxyReplyCode.NetworkUnreachable;
                                        bindEP = new IPEndPoint(IPAddress.Any, 0);
                                    }
                                    else
                                    {
                                        _remoteSocket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                                        _remoteSocket.Bind(endPoint);
                                        _remoteSocket.Listen(1);

                                        reply = SocksProxyReplyCode.Succeeded;
                                        bindEP = new IPEndPoint(networkInfo.LocalIP, (_remoteSocket.LocalEndPoint as IPEndPoint).Port);
                                    }
                                }
                            }
                            break;

                        case SocksProxyRequestCommand.UdpAssociate:
                            {
                                EndPoint endPoint = null;

                                switch (_localSocket.LocalEndPoint.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                        endPoint = new IPEndPoint(IPAddress.Any, 0);
                                        break;

                                    case AddressFamily.InterNetworkV6:
                                        endPoint = new IPEndPoint(IPAddress.Any, 0);
                                        break;

                                    default:
                                        break;
                                }

                                if (endPoint == null)
                                {
                                    reply = SocksProxyReplyCode.AddressTypeNotSupported;
                                    bindEP = new IPEndPoint(IPAddress.Any, 0);
                                }
                                else
                                {
                                    _udpRelaySocket = new Socket(endPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                                    _udpRelaySocket.Bind(endPoint);

                                    _remoteSocket = new Socket(endPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                                    _remoteSocket.Bind(endPoint);

                                    reply = SocksProxyReplyCode.Succeeded;
                                    bindEP = new IPEndPoint((_localSocket.LocalEndPoint as IPEndPoint).Address, (_udpRelaySocket.LocalEndPoint as IPEndPoint).Port);
                                }
                            }
                            break;

                        default:
                            reply = SocksProxyReplyCode.CommandNotSupported;
                            bindEP = new IPEndPoint(IPAddress.Any, 0);
                            break;
                    }

                    //send response
                    await new SocksProxyReply(reply, bindEP).WriteToAsync(localStream);
                    await localStream.FlushAsync();

                    //final command process
                    switch (request.Command)
                    {
                        case SocksProxyRequestCommand.Connect:
                            {
                                //pipe sockets
                                _ = _localSocket.CopyToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                _ = _remoteSocket.CopyToAsync(_localSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                dontDispose = true;
                            }
                            break;

                        case SocksProxyRequestCommand.Bind:
                            {
                                Socket socket = null;

                                try
                                {
                                    socket = await _remoteSocket.AcceptAsync().WithTimeout(CLIENT_WAIT_TIMEOUT);
                                }
                                catch
                                {
                                    //send second reply
                                    await new SocksProxyReply(SocksProxyReplyCode.GeneralSocksServerFailure, _remoteSocket.RemoteEndPoint).WriteToAsync(localStream);
                                    await localStream.FlushAsync();
                                }

                                if (socket != null)
                                {
                                    _remoteSocket.Dispose();
                                    _remoteSocket = socket;

                                    //send second reply
                                    await new SocksProxyReply(SocksProxyReplyCode.Succeeded, _remoteSocket.RemoteEndPoint).WriteToAsync(localStream);
                                    await localStream.FlushAsync();

                                    //pipe sockets
                                    _ = _localSocket.CopyToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                    _ = _remoteSocket.CopyToAsync(_localSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                    dontDispose = true;
                                }
                            }
                            break;

                        case SocksProxyRequestCommand.UdpAssociate:
                            {
                                using (SocksProxyUdpAssociateHandler udpHandler = new SocksProxyUdpAssociateHandler(_localSocket, _udpRelaySocket, new IPEndPoint((_localSocket.RemoteEndPoint as IPEndPoint).Address, (request.DestinationEndPoint as IPEndPoint).Port)))
                                {
                                    //remoteSocket to udpHandler pipe
                                    _ = CopyToAsync(_remoteSocket, udpHandler);

                                    //udpHandler to remoteSocket pipe
                                    byte[] buffer = new byte[64 * 1024];

                                    while (true)
                                    {
                                        UdpReceiveFromResult result = await udpHandler.ReceiveFromAsync(buffer, 0, buffer.Length);
                                        await _remoteSocket.SendToAsync(buffer, 0, result.BytesReceived, result.RemoteEndPoint);
                                    }
                                }
                            }
                    }

                    #endregion
                }
                finally
                {
                    if (!dontDispose)
                        Dispose();
                }
            }

            #endregion
        }
    }
}
