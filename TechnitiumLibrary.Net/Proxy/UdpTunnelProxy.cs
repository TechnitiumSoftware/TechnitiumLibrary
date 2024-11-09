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
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class UdpTunnelProxy : IDisposable
    {
        #region variables

        readonly IProxyServerUdpAssociateHandler _proxyUdpHandler;
        readonly Socket _remoteSocket;
        readonly EndPoint _remoteEP;

        readonly Socket _tunnelSocket;
        readonly IPEndPoint _tunnelLocalEP;

        EndPoint _tunnelRemoteEP;

        #endregion

        #region constructor

        public UdpTunnelProxy(IProxyServerUdpAssociateHandler proxyUdpHandler, EndPoint remoteEP)
        {
            _proxyUdpHandler = proxyUdpHandler;
            _remoteEP = remoteEP;

            //start local tunnel socket
            _tunnelSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _tunnelSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            _tunnelLocalEP = _tunnelSocket.LocalEndPoint as IPEndPoint;

            _ = Task.Factory.StartNew(PipeTunnelToProxy, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
        }

        public UdpTunnelProxy(Socket remoteSocket, EndPoint remoteEP)
        {
            _remoteSocket = remoteSocket;
            _remoteEP = remoteEP;

            //start local tunnel socket
            _tunnelSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _tunnelSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            _tunnelLocalEP = _tunnelSocket.LocalEndPoint as IPEndPoint;

            _ = Task.Factory.StartNew(PipeTunnelToRemoteSocket, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _tunnelSocket?.Dispose();

            _proxyUdpHandler?.Dispose();

            GC.SuppressFinalize(this);

            _disposed = true;
        }

        #endregion

        #region private

        private void PipeTunnelToProxy()
        {
            _ = CopyTunnelToProxyAsync();
            _ = CopyProxyToTunnelAsync();
        }

        private async Task CopyTunnelToProxyAsync()
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                EndPoint anyEP = SocketExtensions.GetEndPointAnyFor(_tunnelSocket.AddressFamily);

                while (true)
                {
                    SocketReceiveFromResult result = await _tunnelSocket.ReceiveFromAsync(buffer, SocketFlags.None, anyEP);

                    _tunnelRemoteEP = result.RemoteEndPoint; //client EP may change in case of HTTP/3 SocketsHttpHandler

                    await _proxyUdpHandler.SendToAsync(new ArraySegment<byte>(buffer, 0, result.ReceivedBytes), _remoteEP);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                Dispose();
            }
        }

        private async Task CopyProxyToTunnelAsync()
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                while (true)
                {
                    SocketReceiveFromResult result = await _proxyUdpHandler.ReceiveFromAsync(buffer);

                    if (_tunnelRemoteEP is not null)
                        await _tunnelSocket.SendToAsync(new ArraySegment<byte>(buffer, 0, result.ReceivedBytes), SocketFlags.None, _tunnelRemoteEP);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                Dispose();
            }
        }

        private void PipeTunnelToRemoteSocket()
        {
            _ = CopyTunnelToRemoteSocketAsync();
            _ = CopyRemoteSocketToTunnelAsync();
        }

        private async Task CopyTunnelToRemoteSocketAsync()
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);

            try
            {
                EndPoint anyEP = SocketExtensions.GetEndPointAnyFor(_tunnelSocket.AddressFamily);

                while (true)
                {
                    SocketReceiveFromResult result = await _tunnelSocket.ReceiveFromAsync(buffer, SocketFlags.None, anyEP);

                    _tunnelRemoteEP = result.RemoteEndPoint; //client EP may change in case of HTTP/3 SocketsHttpHandler

                    await _remoteSocket.SendToAsync(new ArraySegment<byte>(buffer, 0, result.ReceivedBytes), _remoteEP);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                Dispose();
            }
        }

        private async Task CopyRemoteSocketToTunnelAsync()
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                EndPoint anyEP = SocketExtensions.GetEndPointAnyFor(_remoteSocket.AddressFamily);

                while (true)
                {
                    SocketReceiveFromResult result = await _remoteSocket.ReceiveFromAsync(buffer, SocketFlags.None, anyEP);

                    if (_tunnelRemoteEP is not null)
                        await _tunnelSocket.SendToAsync(new ArraySegment<byte>(buffer, 0, result.ReceivedBytes), SocketFlags.None, _tunnelRemoteEP);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
                Dispose();
            }
        }

        #endregion

        #region properties

        public EndPoint RemoteEndPoint
        { get { return _remoteEP; } }

        public IPEndPoint TunnelEndPoint
        { get { return _tunnelLocalEP; } }

        public bool IsBroken
        { get { return _disposed; } }

        #endregion
    }
}
