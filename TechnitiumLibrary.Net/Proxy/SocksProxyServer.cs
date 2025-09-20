/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
            _listener.NoDelay = true;

            _localEP = (IPEndPoint)_listener.LocalEndPoint;
            _connectionManager = connectionManager;
            _authenticationManager = authenticationManager;

            if (_connectionManager == null)
                _connectionManager = new DefaultProxyServerConnectionManager();

            //accept requests async
            int tasks = Environment.ProcessorCount;
            for (int i = 0; i < tasks; i++)
                _ = Task.Factory.StartNew(AcceptRequestAsync, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_listener != null)
                    _listener.Dispose();

                foreach (KeyValuePair<ProxyServerSession, object> session in _sessions)
                    session.Key.Dispose();

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
                        _ = session.StartAsync();
                }
            }
            finally
            {
                Dispose();
            }
        }

        #endregion

        #region static

        internal static async Task<EndPoint> ReadEndPointAsync(Stream s, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2];

            await s.ReadExactlyAsync(buffer, 0, 1, cancellationToken);
            SocksAddressType addressType = (SocksAddressType)buffer[0];

            switch (addressType)
            {
                case SocksAddressType.IPv4Address:
                    {
                        byte[] addressBytes = new byte[4];
                        await s.ReadExactlyAsync(addressBytes, 0, 4, cancellationToken);
                        await s.ReadExactlyAsync(buffer, 0, 2, cancellationToken);
                        Array.Reverse(buffer, 0, 2);

                        return new IPEndPoint(new IPAddress(addressBytes), BitConverter.ToUInt16(buffer, 0));
                    }

                case SocksAddressType.IPv6Address:
                    {
                        byte[] addressBytes = new byte[16];
                        await s.ReadExactlyAsync(addressBytes, 0, 16, cancellationToken);
                        await s.ReadExactlyAsync(buffer, 0, 2, cancellationToken);
                        Array.Reverse(buffer, 0, 2);

                        return new IPEndPoint(new IPAddress(addressBytes), BitConverter.ToUInt16(buffer, 0));
                    }

                case SocksAddressType.DomainName:
                    {
                        await s.ReadExactlyAsync(buffer, 0, 1, cancellationToken);
                        byte[] addressBytes = new byte[buffer[0]];
                        await s.ReadExactlyAsync(addressBytes, 0, addressBytes.Length, cancellationToken);
                        string domain = Encoding.ASCII.GetString(addressBytes);

                        await s.ReadExactlyAsync(buffer, 0, 2, cancellationToken);
                        Array.Reverse(buffer, 0, 2);

                        if (IPAddress.TryParse(domain, out IPAddress address)) //some socks clients send ip address with domain address type
                            return new IPEndPoint(address, BitConverter.ToUInt16(buffer, 0));
                        else
                            return new DomainEndPoint(domain, BitConverter.ToUInt16(buffer, 0));
                    }

                default:
                    return null;
            }
        }

        internal static async Task WriteEndPointAsync(EndPoint endPoint, Stream s, CancellationToken cancellationToken)
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
                            throw new NotSupportedException("Address Family not supported.");

                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("Address Family not supported.");
            }

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);

            await s.WriteAsync(new byte[] { (byte)addressType }, cancellationToken);
            await s.WriteAsync(address, cancellationToken);
            await s.WriteAsync(portBytes.AsMemory(0, 2), cancellationToken);
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

            Socket _remoteSocket;
            IProxyServerBindHandler _bindHandler;
            Socket _udpRelaySocket;

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

                        if (_remoteSocket != null)
                            _remoteSocket.Dispose();

                        if (_bindHandler != null)
                            _bindHandler.Dispose();

                        if (_udpRelaySocket != null)
                            _udpRelaySocket.Dispose();
                    }

                    _disposed = true;
                    Disposed?.Invoke(this, EventArgs.Empty);
                }
            }

            #endregion

            #region private

            private async Task CopyToAsync(IProxyServerUdpAssociateHandler src, IProxyServerUdpAssociateHandler dst)
            {
                try
                {
                    byte[] buffer = new byte[64 * 1024];

                    while (true)
                    {
                        SocketReceiveFromResult result = await src.ReceiveFromAsync(buffer);
                        await dst.SendToAsync(new ArraySegment<byte>(buffer, 0, result.ReceivedBytes), result.RemoteEndPoint);
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

                    SocksProxyNegotiationRequest negotiationRequest = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                    {
                        return SocksProxyNegotiationRequest.ReadRequestAsync(localStream, cancellationToken1);
                    }, CLIENT_WAIT_TIMEOUT);

                    if (!negotiationRequest.IsVersionSupported)
                    {
                        await new SocksProxyNegotiationReply(SocksProxyAuthenticationMethod.NoAcceptableMethods).WriteToAsync(localStream);
                        await localStream.FlushAsync();
                        return;
                    }

                    //match method and authenticate
                    bool methodMatched = false;
                    SocksProxyAuthenticationMethod serverMethod = _authenticationManager == null ? SocksProxyAuthenticationMethod.NoAuthenticationRequired : SocksProxyAuthenticationMethod.UsernamePassword;
                    string username = null;

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

                                    SocksProxyAuthenticationRequest authenticationRequest = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                    {
                                        return SocksProxyAuthenticationRequest.ReadRequestAsync(localStream, cancellationToken1);
                                    }, CLIENT_WAIT_TIMEOUT);

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
                                    username = authenticationRequest.Username;
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
                    SocksProxyRequest request = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                    {
                        return SocksProxyRequest.ReadRequestAsync(localStream, cancellationToken1);
                    }, CLIENT_WAIT_TIMEOUT);

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
                                    if (_connectionManager is IProxyServerExtendedConnectionManager extendedConnectionManager)
                                        _remoteSocket = await extendedConnectionManager.ConnectAsync(request.DestinationEndPoint, username);
                                    else
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
                                _bindHandler = await _connectionManager.GetBindHandlerAsync(request.DestinationEndPoint.AddressFamily);

                                reply = _bindHandler.ReplyCode;
                                bindEP = _bindHandler.ProxyLocalEndPoint;
                            }
                            break;

                        case SocksProxyRequestCommand.UdpAssociate:
                            {
                                switch (_localSocket.LocalEndPoint.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                    case AddressFamily.InterNetworkV6:
                                        IPEndPoint localEP = new IPEndPoint((_localSocket.LocalEndPoint as IPEndPoint).Address, 0);

                                        _udpRelaySocket = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                                        _udpRelaySocket.Bind(localEP);

                                        reply = SocksProxyReplyCode.Succeeded;
                                        bindEP = _udpRelaySocket.LocalEndPoint as IPEndPoint;
                                        break;

                                    default:
                                        reply = SocksProxyReplyCode.AddressTypeNotSupported;
                                        bindEP = new IPEndPoint(IPAddress.Any, 0);
                                        break;
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

                    if (reply != SocksProxyReplyCode.Succeeded)
                        return; //nothing to do further

                    //final command process
                    switch (request.Command)
                    {
                        case SocksProxyRequestCommand.Connect:
                            {
                                //pipe sockets
                                _ = _localSocket.PipeToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                dontDispose = true;
                            }
                            break;

                        case SocksProxyRequestCommand.Bind:
                            {
                                try
                                {
                                    _remoteSocket = await TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                    {
                                        return _bindHandler.AcceptAsync(cancellationToken1);
                                    }, CLIENT_WAIT_TIMEOUT);
                                }
                                catch (SocksProxyException ex)
                                {
                                    //send second reply
                                    await new SocksProxyReply(ex.ReplyCode, _bindHandler.ProxyLocalEndPoint).WriteToAsync(localStream);
                                    await localStream.FlushAsync();
                                }
                                catch
                                {
                                    //send second reply
                                    await new SocksProxyReply(SocksProxyReplyCode.GeneralSocksServerFailure, _bindHandler.ProxyLocalEndPoint).WriteToAsync(localStream);
                                    await localStream.FlushAsync();
                                }

                                if (_remoteSocket != null)
                                {
                                    _bindHandler.Dispose();

                                    //send second reply
                                    await new SocksProxyReply(SocksProxyReplyCode.Succeeded, _bindHandler.ProxyRemoteEndPoint).WriteToAsync(localStream);
                                    await localStream.FlushAsync();

                                    //pipe sockets
                                    _ = _localSocket.PipeToAsync(_remoteSocket).ContinueWith(delegate (Task prevTask) { Dispose(); });
                                    dontDispose = true;
                                }
                            }
                            break;

                        case SocksProxyRequestCommand.UdpAssociate:
                            {
                                EndPoint localEP = null;

                                switch (_localSocket.LocalEndPoint.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                        localEP = new IPEndPoint(IPAddress.Any, 0);
                                        break;

                                    case AddressFamily.InterNetworkV6:
                                        localEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                                        break;

                                    default:
                                        throw new NotSupportedException();
                                }

                                using (IProxyServerUdpAssociateHandler udpRemoteHandler = await _connectionManager.GetUdpAssociateHandlerAsync(localEP))
                                {
                                    using (IProxyServerUdpAssociateHandler udpLocalHandler = new SocksProxyUdpAssociateHandler(_localSocket, _udpRelaySocket, new IPEndPoint((_localSocket.RemoteEndPoint as IPEndPoint).Address, (request.DestinationEndPoint as IPEndPoint).Port)))
                                    {
                                        _ = CopyToAsync(udpRemoteHandler, udpLocalHandler);
                                        await CopyToAsync(udpLocalHandler, udpRemoteHandler);
                                    }
                                }
                            }
                            break;
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
