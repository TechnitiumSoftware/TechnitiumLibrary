/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class DefaultProxyServerConnectionManager : IProxyServerConnectionManager
    {
        #region variables

        protected const int SOL_SOCKET = 1;
        protected const int SO_BINDTODEVICE = 25;

        #endregion

        #region public

        public virtual async Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            if (remoteEP.AddressFamily == AddressFamily.Unspecified)
                remoteEP = await remoteEP.GetIPEndPointAsync();

            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            await socket.ConnectAsync(remoteEP);

            socket.NoDelay = true;

            return socket;
        }

        public virtual Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            IProxyServerBindHandler bindHandler = new BindHandler(family);
            return Task.FromResult(bindHandler);
        }

        public virtual Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            IProxyServerUdpAssociateHandler udpHandler = new UdpSocketHandler(localEP);
            return Task.FromResult(udpHandler);
        }

        #endregion

        protected class BindHandler : IProxyServerBindHandler
        {
            #region variables

            readonly Socket _socket;

            readonly SocksProxyReplyCode _replyCode;
            readonly EndPoint _bindEP;

            EndPoint _remoteEP;

            #endregion

            #region constructor

            public BindHandler(AddressFamily family)
            {
                EndPoint localEP = null;
                NetworkInfo networkInfo = null;

                switch (family)
                {
                    case AddressFamily.InterNetwork:
                        localEP = new IPEndPoint(IPAddress.Any, 0);
                        networkInfo = NetUtilities.GetDefaultIPv4NetworkInfo();
                        break;

                    case AddressFamily.InterNetworkV6:
                        localEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                        networkInfo = NetUtilities.GetDefaultIPv6NetworkInfo();
                        break;

                    default:
                        _replyCode = SocksProxyReplyCode.AddressTypeNotSupported;
                        _bindEP = new IPEndPoint(IPAddress.Any, 0);
                        break;
                }

                if (localEP != null)
                {
                    if (networkInfo == null)
                    {
                        _replyCode = SocksProxyReplyCode.NetworkUnreachable;
                        _bindEP = new IPEndPoint(IPAddress.Any, 0);
                    }
                    else
                    {
                        _socket = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                        _socket.Bind(localEP);
                        _socket.Listen(1);
                        _socket.NoDelay = true;

                        _replyCode = SocksProxyReplyCode.Succeeded;
                        _bindEP = new IPEndPoint(networkInfo.LocalIP, (_socket.LocalEndPoint as IPEndPoint).Port);
                    }
                }
            }

            public BindHandler(IPEndPoint bindEP, byte[] bindToInterfaceName = null)
            {
                switch (bindEP.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                    case AddressFamily.InterNetworkV6:
                        _socket = new Socket(bindEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (bindToInterfaceName is not null)
                            _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, bindToInterfaceName);

                        _socket.Bind(bindEP);
                        _socket.Listen(1);
                        _socket.NoDelay = true;

                        _replyCode = SocksProxyReplyCode.Succeeded;
                        _bindEP = new IPEndPoint(bindEP.Address, (_socket.LocalEndPoint as IPEndPoint).Port);
                        break;

                    default:
                        _replyCode = SocksProxyReplyCode.AddressTypeNotSupported;
                        _bindEP = new IPEndPoint(IPAddress.Any, 0);
                        break;
                }
            }

            #endregion

            #region IDisposable

            bool _disposed;

            protected virtual void Dispose(bool disposing)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_socket != null)
                        _socket.Dispose();
                }

                _disposed = true;
            }

            public void Dispose()
            {
                Dispose(true);
            }

            #endregion

            #region public

            public async Task<Socket> AcceptAsync()
            {
                Socket remoteSocket = await _socket.AcceptAsync();
                _remoteEP = remoteSocket.RemoteEndPoint;

                return remoteSocket;
            }

            #endregion

            #region properties

            public SocksProxyReplyCode ReplyCode
            { get { return _replyCode; } }

            public EndPoint ProxyRemoteEndPoint
            { get { return _remoteEP; } }

            public EndPoint ProxyLocalEndPoint
            { get { return _bindEP; } }

            #endregion
        }

        protected class UdpSocketHandler : IProxyServerUdpAssociateHandler
        {
            #region variables

            readonly Socket _socket;

            #endregion

            #region constructor

            public UdpSocketHandler(EndPoint bindEP, byte[] bindToInterfaceName = null)
            {
                _socket = new Socket(bindEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                if (bindToInterfaceName is not null)
                    _socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, bindToInterfaceName);

                _socket.Bind(bindEP);
            }

            #endregion

            #region IDisposable

            bool _disposed;

            protected virtual void Dispose(bool disposing)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_socket != null)
                        _socket.Dispose();
                }

                _disposed = true;
            }

            public void Dispose()
            {
                Dispose(true);
            }

            #endregion

            #region public

            public Task<int> SendToAsync(ArraySegment<byte> buffer, EndPoint remoteEP)
            {
                return _socket.SendToAsync(buffer, SocketFlags.None, remoteEP);
            }

            public Task<SocketReceiveFromResult> ReceiveFromAsync(ArraySegment<byte> buffer)
            {
                return _socket.ReceiveFromAsync(buffer, SocketFlags.None, SocketExtension.GetEndPointAnyFor(_socket.AddressFamily));
            }

            #endregion
        }
    }
}
