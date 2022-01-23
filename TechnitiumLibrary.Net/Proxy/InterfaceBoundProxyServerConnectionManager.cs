/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class InterfaceBoundProxyServerConnectionManager : DefaultProxyServerConnectionManager
    {
        #region variables

        readonly IPEndPoint _bindEP;
        readonly byte[] _bindToInterfaceName;

        #endregion

        #region constructor

        public InterfaceBoundProxyServerConnectionManager(IPAddress bindAddress)
        {
            _bindEP = new IPEndPoint(bindAddress, 0);

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    break;

                case PlatformID.Unix:
                    //find interface names
                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        foreach (UnicastIPAddressInformation ip in nic.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.Equals(bindAddress))
                            {
                                _bindToInterfaceName = Encoding.ASCII.GetBytes(nic.Name);
                                break;
                            }
                        }

                        if (_bindToInterfaceName is not null)
                            break;
                    }

                    break;

                default:
                    throw new PlatformNotSupportedException();
            }
        }

        #endregion

        #region public

        public override async Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
        {
            if (remoteEP.AddressFamily == AddressFamily.Unspecified)
                remoteEP = await remoteEP.GetIPEndPointAsync(_bindEP.AddressFamily);

            if (_bindEP.AddressFamily != remoteEP.AddressFamily)
                throw new SocketException((int)SocketError.NetworkUnreachable);

            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            if (_bindToInterfaceName is not null)
                socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, _bindToInterfaceName);

            socket.Bind(_bindEP);

            await socket.ConnectAsync(remoteEP, cancellationToken);

            socket.NoDelay = true;

            return socket;
        }

        public override Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            if (_bindEP.AddressFamily != family)
                throw new SocketException((int)SocketError.NetworkUnreachable);

            IProxyServerBindHandler bindHandler = new BindHandler(_bindEP, _bindToInterfaceName);
            return Task.FromResult(bindHandler);
        }

        public override Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            if (_bindEP.AddressFamily != localEP.AddressFamily)
                throw new SocketException((int)SocketError.NetworkUnreachable);

            IProxyServerUdpAssociateHandler udpHandler = new UdpSocketHandler(_bindEP, _bindToInterfaceName);
            return Task.FromResult(udpHandler);
        }

        #endregion

        #region properties

        public IPAddress BindAddress
        { get { return _bindEP.Address; } }

        #endregion
    }
}
