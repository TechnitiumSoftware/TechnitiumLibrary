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
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class InterfaceBoundProxyServerConnectionManager : DefaultProxyServerConnectionManager
    {
        #region variables

        readonly IPEndPoint _bindIpv4EP;
        readonly IPEndPoint _bindIpv6EP;

        #endregion

        #region constructor

        public InterfaceBoundProxyServerConnectionManager(IPAddress bindIpv4Address = null, IPAddress bindIpv6Address = null)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                throw new PlatformNotSupportedException();

            if ((bindIpv4Address == null) && (bindIpv6Address == null))
                throw new ArgumentNullException("At least one bind address must be specified.");

            if (bindIpv4Address != null)
                _bindIpv4EP = new IPEndPoint(bindIpv4Address, 0);

            if (bindIpv6Address != null)
                _bindIpv6EP = new IPEndPoint(bindIpv6Address, 0);
        }

        #endregion

        #region private

        private IPEndPoint GetBindEP(AddressFamily family)
        {
            switch (family)
            {
                case AddressFamily.InterNetwork:
                    if (_bindIpv4EP == null)
                        throw new SocketException((int)SocketError.NetworkUnreachable);

                    return _bindIpv4EP;

                case AddressFamily.InterNetworkV6:
                    if (_bindIpv6EP == null)
                        throw new SocketException((int)SocketError.NetworkUnreachable);

                    return _bindIpv6EP;

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region public

        public override async Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            if (remoteEP.AddressFamily == AddressFamily.Unspecified)
            {
                AddressFamily family;

                if (_bindIpv6EP == null)
                    family = AddressFamily.InterNetwork;
                else
                    family = AddressFamily.InterNetworkV6;

                remoteEP = await remoteEP.GetIPEndPointAsync(family);
            }

            IPEndPoint bindEP = GetBindEP(remoteEP.AddressFamily);

            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            socket.Bind(bindEP);

            await socket.ConnectAsync(remoteEP);

            socket.NoDelay = true;

            return socket;
        }

        public override Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            IPEndPoint bindEP = GetBindEP(family);
            IProxyServerBindHandler bindHandler = new BindHandler(bindEP);
            return Task.FromResult(bindHandler);
        }

        public override Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            IPEndPoint bindEP = GetBindEP(localEP.AddressFamily);
            IProxyServerUdpAssociateHandler udpHandler = new UdpSocketHandler(bindEP);
            return Task.FromResult(udpHandler);
        }

        #endregion

        #region properties

        public IPAddress BindAddress
        { get { return _bindIpv4EP.Address; } }

        #endregion
    }
}
