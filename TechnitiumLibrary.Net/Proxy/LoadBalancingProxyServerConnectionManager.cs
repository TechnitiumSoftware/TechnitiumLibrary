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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class LoadBalancingProxyServerConnectionManager : IProxyServerConnectionManager, IDisposable
    {
        #region events

        public event EventHandler<Exception> Errors;

        #endregion

        #region variables

        static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        readonly IReadOnlyList<IProxyServerConnectionManager> _ipv4ConnectionManagers;
        readonly IReadOnlyList<IProxyServerConnectionManager> _ipv6ConnectionManagers;
        readonly IReadOnlyCollection<EndPoint> _connectivityCheckEPs;
        readonly bool _redundancyOnly;

        IReadOnlyList<IProxyServerConnectionManager> _workingIpv4ConnectionManagers;
        IReadOnlyList<IProxyServerConnectionManager> _workingIpv6ConnectionManagers;

        readonly Timer _networkCheckTimer;
        const int NETWORK_CHECK_TIMER_INITIAL_INTERVAL = 1000;
        const int NETWORK_CHECK_TIMER_PERIODIC_INTERVAL = 30000;
        const int NETWORK_CHECK_CONNECTION_TIMEOUT = 15000;

        #endregion

        #region constructor

        public LoadBalancingProxyServerConnectionManager(IReadOnlyList<IProxyServerConnectionManager> ipv4ConnectionManagers, IReadOnlyList<IProxyServerConnectionManager> ipv6ConnectionManagers, IReadOnlyCollection<EndPoint> connectivityCheckEPs = null, bool redundancyOnly = false)
        {
            _ipv4ConnectionManagers = ipv4ConnectionManagers;
            _ipv6ConnectionManagers = ipv6ConnectionManagers;
            _connectivityCheckEPs = connectivityCheckEPs;
            _redundancyOnly = redundancyOnly;

            if (_connectivityCheckEPs == null)
                _connectivityCheckEPs = new EndPoint[] { new DomainEndPoint("www.google.com", 443), new DomainEndPoint("www.microsoft.com", 443) };

            _workingIpv4ConnectionManagers = _ipv4ConnectionManagers;
            _workingIpv6ConnectionManagers = _ipv6ConnectionManagers;

            _networkCheckTimer = new Timer(async delegate (object state)
            {
                try
                {
                    //filter out working connection managers from available connection managers
                    List<Task<IProxyServerConnectionManager>> ipv4Tasks = new List<Task<IProxyServerConnectionManager>>();
                    List<Task<IProxyServerConnectionManager>> ipv6Tasks = new List<Task<IProxyServerConnectionManager>>();

                    foreach (IProxyServerConnectionManager connectionManager in _ipv4ConnectionManagers)
                        ipv4Tasks.Add(CheckConnectivityAsync(connectionManager));

                    foreach (IProxyServerConnectionManager connectionManager in _ipv6ConnectionManagers)
                        ipv6Tasks.Add(CheckConnectivityAsync(connectionManager));

                    IProxyServerConnectionManager[] ipv4Results = await Task.WhenAll(ipv4Tasks);
                    IProxyServerConnectionManager[] ipv6Results = await Task.WhenAll(ipv6Tasks);

                    List<IProxyServerConnectionManager> workingIpv4ConnectionManagers = new List<IProxyServerConnectionManager>();
                    List<IProxyServerConnectionManager> workingIpv6ConnectionManagers = new List<IProxyServerConnectionManager>();

                    if (_redundancyOnly)
                    {
                        foreach (IProxyServerConnectionManager connectionManager in _ipv4ConnectionManagers)
                        {
                            foreach (IProxyServerConnectionManager result in ipv4Results)
                            {
                                if (ReferenceEquals(connectionManager, result))
                                {
                                    workingIpv4ConnectionManagers.Add(result);
                                    break;
                                }
                            }

                            if (workingIpv4ConnectionManagers.Count > 0)
                                break;
                        }

                        foreach (IProxyServerConnectionManager connectionManager in _ipv6ConnectionManagers)
                        {
                            foreach (IProxyServerConnectionManager result in ipv6Results)
                            {
                                if (ReferenceEquals(connectionManager, result))
                                {
                                    workingIpv6ConnectionManagers.Add(result);
                                    break;
                                }
                            }

                            if (workingIpv6ConnectionManagers.Count > 0)
                                break;
                        }
                    }
                    else
                    {
                        foreach (IProxyServerConnectionManager result in ipv4Results)
                        {
                            if (result is not null)
                                workingIpv4ConnectionManagers.Add(result);
                        }

                        foreach (IProxyServerConnectionManager result in ipv6Results)
                        {
                            if (result is not null)
                                workingIpv6ConnectionManagers.Add(result);
                        }
                    }

                    _workingIpv4ConnectionManagers = workingIpv4ConnectionManagers;
                    _workingIpv6ConnectionManagers = workingIpv6ConnectionManagers;
                }
                catch (Exception ex)
                {
                    Errors?.Invoke(this, ex);
                }
                finally
                {
                    if (!_disposed)
                        _networkCheckTimer.Change(NETWORK_CHECK_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                }
            }, null, Timeout.Infinite, Timeout.Infinite);

            _networkCheckTimer.Change(NETWORK_CHECK_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
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
                if (_networkCheckTimer != null)
                    _networkCheckTimer.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region static

        private static int GetRandomNumber()
        {
            Span<byte> randomBuffer = stackalloc byte[4];
            _rng.GetBytes(randomBuffer);

            return BitConverter.ToInt32(randomBuffer) & 0x7FFFFFFF;
        }

        #endregion

        #region private

        private async Task<IProxyServerConnectionManager> CheckConnectivityAsync(IProxyServerConnectionManager connectionManager)
        {
            Exception lastException = null;

            foreach (EndPoint connectivityCheckEP in _connectivityCheckEPs)
            {
                try
                {
                    using (Socket socket = await connectionManager.ConnectAsync(connectivityCheckEP).WithTimeout(NETWORK_CHECK_CONNECTION_TIMEOUT))
                    { }

                    return connectionManager;
                }
                catch (Exception ex)
                {
                    lastException = ex;
                }
            }

            Errors?.Invoke(this, lastException);
            return null;
        }

        private IProxyServerConnectionManager GetConnectionManager(AddressFamily family)
        {
            IReadOnlyList<IProxyServerConnectionManager> workingConnectionManagers;

            switch (family)
            {
                case AddressFamily.InterNetwork:
                    workingConnectionManagers = _workingIpv4ConnectionManagers;
                    break;

                case AddressFamily.InterNetworkV6:
                    workingConnectionManagers = _workingIpv6ConnectionManagers;
                    break;

                default:
                    throw new NotSupportedException();
            }

            if (workingConnectionManagers.Count == 0)
                throw new SocketException((int)SocketError.NetworkUnreachable);

            if ((workingConnectionManagers.Count == 1) || _redundancyOnly)
                return workingConnectionManagers[0];

            return workingConnectionManagers[GetRandomNumber() % workingConnectionManagers.Count];
        }

        #endregion

        #region public

        public async Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            if (remoteEP.AddressFamily == AddressFamily.Unspecified)
            {
                bool ipv4Available = _workingIpv4ConnectionManagers.Count > 0;
                bool ipv6Available = _workingIpv6ConnectionManagers.Count > 0;

                if (ipv4Available && ipv6Available)
                    remoteEP = await remoteEP.GetIPEndPointAsync();
                else if (ipv4Available)
                    remoteEP = await remoteEP.GetIPEndPointAsync(AddressFamily.InterNetwork);
                else if (ipv6Available)
                    remoteEP = await remoteEP.GetIPEndPointAsync(AddressFamily.InterNetworkV6);
                else
                    throw new SocketException((int)SocketError.NetworkUnreachable);
            }

            return await GetConnectionManager(remoteEP.AddressFamily).ConnectAsync(remoteEP);
        }

        public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            return GetConnectionManager(family).GetBindHandlerAsync(family);
        }

        public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            return GetConnectionManager(localEP.AddressFamily).GetUdpAssociateHandlerAsync(localEP);
        }

        #endregion
    }
}
