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
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public class LoadBalancingProxyServerConnectionManager : IProxyServerConnectionManager, IDisposable
    {
        #region events

        public event EventHandler<Exception> Errors;

        #endregion

        #region variables

        static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        readonly IReadOnlyList<IProxyServerConnectionManager> _connectionManagers;
        readonly IReadOnlyCollection<EndPoint> _connectivityCheckEPs;
        readonly bool _redundancyOnly;

        IReadOnlyList<IProxyServerConnectionManager> _workingConnectionManagers;

        readonly Timer _networkCheckTimer;
        const int NETWORK_CHECK_TIMER_INITIAL_INTERVAL = 1000;
        const int NETWORK_CHECK_TIMER_PERIODIC_INTERVAL = 30000;
        const int NETWORK_CHECK_CONNECTION_TIMEOUT = 15000;

        #endregion

        #region constructor

        public LoadBalancingProxyServerConnectionManager(IReadOnlyList<IProxyServerConnectionManager> connectionManagers, IReadOnlyCollection<EndPoint> connectivityCheckEPs = null, bool redundancyOnly = false)
        {
            _connectionManagers = connectionManagers;
            _connectivityCheckEPs = connectivityCheckEPs;
            _redundancyOnly = redundancyOnly;

            if (_connectivityCheckEPs == null)
                _connectivityCheckEPs = new EndPoint[] { new DomainEndPoint("www.google.com", 443), new DomainEndPoint("www.microsoft.com", 443) };

            _workingConnectionManagers = _connectionManagers;

            _networkCheckTimer = new Timer(async delegate (object state)
            {
                try
                {
                    //filter out working connection managers from available connection managers
                    List<Task<IProxyServerConnectionManager>> tasks = new List<Task<IProxyServerConnectionManager>>();

                    foreach (IProxyServerConnectionManager connectionManager in _connectionManagers)
                        tasks.Add(CheckConnectivityAsync(connectionManager));

                    IProxyServerConnectionManager[] results = await Task.WhenAll(tasks);
                    List<IProxyServerConnectionManager> workingConnectionManagers = new List<IProxyServerConnectionManager>();

                    if (_redundancyOnly)
                    {
                        foreach (IProxyServerConnectionManager connectionManager in _connectionManagers)
                        {
                            foreach (IProxyServerConnectionManager result in results)
                            {
                                if (ReferenceEquals(connectionManager, result))
                                {
                                    workingConnectionManagers.Add(result);
                                    break;
                                }
                            }

                            if (workingConnectionManagers.Count > 0)
                                break;
                        }
                    }
                    else
                    {
                        foreach (IProxyServerConnectionManager result in results)
                        {
                            if (result != null)
                                workingConnectionManagers.Add(result);
                        }
                    }

                    _workingConnectionManagers = workingConnectionManagers;
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

        private IProxyServerConnectionManager GetConnectionManager()
        {
            IReadOnlyList<IProxyServerConnectionManager> workingConnectionManagers = _workingConnectionManagers;
            if ((workingConnectionManagers == null) || (workingConnectionManagers.Count == 0))
                throw new SocketException((int)SocketError.NetworkUnreachable);

            if ((workingConnectionManagers.Count == 1) || _redundancyOnly)
                return workingConnectionManagers[0];

            return workingConnectionManagers[GetRandomNumber() % workingConnectionManagers.Count];
        }

        #endregion

        #region public

        public Task<Socket> ConnectAsync(EndPoint remoteEP)
        {
            return GetConnectionManager().ConnectAsync(remoteEP);
        }

        public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            return GetConnectionManager().GetBindHandlerAsync(family);
        }

        public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            return GetConnectionManager().GetUdpAssociateHandlerAsync(localEP);
        }

        #endregion
    }
}
