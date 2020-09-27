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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Proxy
{
    public class LoadBalancingProxyServerConnectionManager : IProxyServerConnectionManager, IDisposable
    {
        #region variables

        static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        List<Network> _networks = new List<Network>();
        DnsClient _dnsClient = new DnsClient() { Cache = new DnsCache() };

        readonly Timer _networkRefreshTimer;
        const int NETWORK_REFRESH_TIMER_INITIAL_INTERVAL = 1000;
        const int NETWORK_REFRESH_TIMER_PERIODIC_INTERVAL = 30000;

        readonly object _removeNetworkLock = new object();

        #endregion

        #region constructor

        public LoadBalancingProxyServerConnectionManager()
        {
            _networkRefreshTimer = new Timer(async delegate (object state)
            {
                try
                {
                    List<Network> networks = await Network.GetNetworksAsync(_dnsClient);
                    bool preferIPv6 = false;

                    foreach (Network network in networks)
                    {
                        if (network.HasIPv6Access)
                        {
                            preferIPv6 = true;
                            break;
                        }
                    }

                    _networks = networks;
                    _dnsClient = new DnsClient(preferIPv6) { Cache = _dnsClient.Cache };
                }
                finally
                {
                    if (!_disposed)
                        _networkRefreshTimer.Change(NETWORK_REFRESH_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                }

            }, null, Timeout.Infinite, Timeout.Infinite);

            _networkRefreshTimer.Change(NETWORK_REFRESH_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
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
                if (_networkRefreshTimer != null)
                    _networkRefreshTimer.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region static

        private static int GetRandomNumber()
        {
            byte[] randomBuffer = new byte[4];
            _rng.GetBytes(randomBuffer);

            return BitConverter.ToInt32(randomBuffer, 0) & 0x7FFFFFFF;
        }

        #endregion

        #region public

        public async Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            Network network;
            {
                switch (_networks.Count)
                {
                    case 0:
                        network = null;
                        break;

                    case 1:
                        network = _networks[0];
                        break;

                    default:
                        network = _networks[GetRandomNumber() % _networks.Count];
                        break;
                }
            }

            if (remoteEP.AddressFamily == AddressFamily.Unspecified)
            {
                DomainEndPoint domainEndPoint = remoteEP as DomainEndPoint;
                if (domainEndPoint == null)
                    throw new NotSupportedException();

                bool preferIPv6 = (network != null) && network.HasIPv6Access;

                IReadOnlyList<IPAddress> addresses = await _dnsClient.ResolveIPAsync(domainEndPoint.Address, preferIPv6);
                if (addresses.Count == 0)
                    throw new SocketException((int)SocketError.HostNotFound);

                remoteEP = new IPEndPoint(addresses[0], domainEndPoint.Port);
            }

            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            if (network != null)
            {
                IPEndPoint bindEP = network.GetBindEndPoint(remoteEP);
                socket.Bind(bindEP);
            }

            try
            {
                await socket.ConnectAsync(remoteEP);
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.NetworkUnreachable:
                    case SocketError.HostUnreachable:
                        if ((network != null) && (_networks.Count > 0))
                        {
                            if (Monitor.TryEnter(_removeNetworkLock))
                            {
                                try
                                {
                                    List<Network> networks = new List<Network>();

                                    foreach (Network n in _networks)
                                    {
                                        if (n.Equals(network))
                                            continue;

                                        networks.Add(n);
                                    }

                                    _networks = networks;
                                }
                                finally
                                {
                                    Monitor.Exit(_removeNetworkLock);
                                }
                            }
                        }
                        break;
                }

                throw;
            }

            socket.NoDelay = true;

            return socket;
        }

        #endregion

        class Network
        {
            #region variables

            readonly List<Task<IPEndPoint>> _checkNetworkTasks;

            readonly List<IPEndPoint> _ipv4BindEPs = new List<IPEndPoint>();
            readonly List<IPEndPoint> _ipv6BindEPs = new List<IPEndPoint>();

            #endregion

            #region constructor

            private Network(List<Task<IPEndPoint>> checkNetworkTasks)
            {
                _checkNetworkTasks = checkNetworkTasks;
            }

            #endregion

            #region static

            public static async Task<List<Network>> GetNetworksAsync(DnsClient dnsClient)
            {
                List<Network> availableNetworks = new List<Network>();

                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    List<IPEndPoint> bindEPs = new List<IPEndPoint>();

                    {
                        IPInterfaceProperties ipInterface = nic.GetIPProperties();

                        List<IPAddress> _ipv6TempAddresses = new List<IPAddress>();
                        List<IPAddress> _ipv6Addresses = new List<IPAddress>();

                        foreach (GatewayIPAddressInformation gateway in ipInterface.GatewayAddresses)
                        {
                            foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                            {
                                if (ip.Address.AddressFamily != gateway.Address.AddressFamily)
                                    continue;

                                switch (ip.Address.AddressFamily)
                                {
                                    case AddressFamily.InterNetwork:
                                        if (gateway.Address.ConvertIpToNumber() == 0u)
                                        {
                                            bindEPs.Add(new IPEndPoint(ip.Address, 0));
                                        }
                                        else
                                        {
                                            int subnetMaskWidth = ip.IPv4Mask.GetSubnetMaskWidth();

                                            if (ip.Address.GetNetworkAddress(subnetMaskWidth).Equals(gateway.Address.GetNetworkAddress(subnetMaskWidth)))
                                                bindEPs.Add(new IPEndPoint(ip.Address, 0));
                                        }

                                        break;

                                    case AddressFamily.InterNetworkV6:
                                        if (NetUtilities.IsPublicIPv6(ip.Address))
                                        {
                                            if (ip.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred)
                                            {
                                                if (ip.SuffixOrigin == SuffixOrigin.Random)
                                                    _ipv6TempAddresses.Add(ip.Address);
                                                else
                                                    _ipv6Addresses.Add(ip.Address);
                                            }
                                        }

                                        break;
                                }
                            }
                        }

                        if (_ipv6TempAddresses.Count > 0)
                        {
                            foreach (IPAddress address in _ipv6TempAddresses)
                                bindEPs.Add(new IPEndPoint(address, 0));
                        }
                        else if (_ipv6Addresses.Count > 0)
                        {
                            foreach (IPAddress address in _ipv6Addresses)
                                bindEPs.Add(new IPEndPoint(address, 0));
                        }
                    }

                    if (bindEPs.Count > 0)
                    {
                        List<Task<IPEndPoint>> checkNetworkTasks = new List<Task<IPEndPoint>>();

                        foreach (IPEndPoint bindEP in bindEPs)
                            checkNetworkTasks.Add(CheckNetworkAsync(dnsClient, bindEP));

                        availableNetworks.Add(new Network(checkNetworkTasks));
                    }
                }

                List<Network> workingNetworks = new List<Network>();

                foreach (Network network in availableNetworks)
                {
                    await network.SelectWorkingNetworksAsync();

                    if ((network._ipv4BindEPs.Count > 0) || (network._ipv6BindEPs.Count > 0))
                        workingNetworks.Add(network);
                }

                return workingNetworks;
            }

            #endregion

            #region private

            private async Task SelectWorkingNetworksAsync()
            {
                await Task.WhenAll(_checkNetworkTasks);

                foreach (Task<IPEndPoint> checkNetworkTask in _checkNetworkTasks)
                {
                    if (checkNetworkTask.Status == TaskStatus.RanToCompletion)
                    {
                        IPEndPoint bindEP = await checkNetworkTask;

                        if (bindEP.AddressFamily == AddressFamily.InterNetwork)
                            _ipv4BindEPs.Add(bindEP);
                        else
                            _ipv6BindEPs.Add(bindEP);
                    }
                }

                _checkNetworkTasks.Clear();
            }

            private static async Task<IPEndPoint> CheckNetworkAsync(DnsClient dnsClient, IPEndPoint bindEP)
            {
                using (Socket socket = new Socket(bindEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.Bind(bindEP);
                    IReadOnlyList<IPAddress> addresses = await dnsClient.ResolveIPAsync("www.google.com", bindEP.AddressFamily == AddressFamily.InterNetworkV6);
                    await socket.ConnectAsync(addresses.ToArray(), 80);
                }

                return bindEP;
            }

            #endregion

            #region public

            public IPEndPoint GetBindEndPoint(EndPoint remoteEP)
            {
                switch (remoteEP.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        switch (_ipv4BindEPs.Count)
                        {
                            case 0:
                                return new IPEndPoint(IPAddress.Any, 0);

                            case 1:
                                return _ipv4BindEPs[0];

                            default:
                                return _ipv4BindEPs[GetRandomNumber() % _ipv4BindEPs.Count];
                        }

                    case AddressFamily.InterNetworkV6:
                        switch (_ipv6BindEPs.Count)
                        {
                            case 0:
                                return new IPEndPoint(IPAddress.IPv6Any, 0);

                            case 1:
                                return _ipv6BindEPs[0];

                            default:
                                return _ipv6BindEPs[GetRandomNumber() % _ipv6BindEPs.Count];
                        }

                    default:
                        throw new NotSupportedException();
                }
            }

            #endregion

            #region properties

            public bool HasIPv4Access
            { get { return _ipv4BindEPs.Count > 0; } }

            public bool HasIPv6Access
            { get { return _ipv6BindEPs.Count > 0; } }

            #endregion
        }
    }
}
