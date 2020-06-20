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
using System.Linq;
using System.Threading;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public abstract class DnsClientConnection : IDisposable
    {
        #region variables

        readonly static Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = CONNECTION_EXPIRY + MAINTENANCE_TIMER_PERIODIC_INTERVAL;
        const int MAINTENANCE_TIMER_PERIODIC_INTERVAL = 15 * 60 * 1000;
        const int CONNECTION_EXPIRY = 1 * 60 * 60 * 1000;

        protected readonly DnsTransportProtocol _protocol;
        protected readonly NameServerAddress _server;
        protected readonly NetProxy _proxy;

        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, TcpClientConnection>> _existingTcpConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, TcpClientConnection>>();
        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, TlsClientConnection>> _existingTlsConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, TlsClientConnection>>();
        const string NO_PROXY = "NO_PROXY";

        #endregion

        #region constructor

        static DnsClientConnection()
        {
            _maintenanceTimer = new Timer(delegate (object state)
            {
                try
                {
                    DateTime expiryTime = DateTime.UtcNow.AddMilliseconds(CONNECTION_EXPIRY * -1);

                    //cleanup unused tcp connections
                    foreach (NameServerAddress nameServer in _existingTcpConnections.Keys.ToArray())
                    {
                        ConcurrentDictionary<object, TcpClientConnection> existingTcpConnection = _existingTcpConnections[nameServer];

                        foreach (object proxy in existingTcpConnection.Keys.ToArray())
                        {
                            TcpClientConnection connection = existingTcpConnection[proxy];

                            if (connection.LastQueried < expiryTime)
                                existingTcpConnection.TryRemove(proxy, out _);
                        }

                        if (existingTcpConnection.IsEmpty)
                            _existingTcpConnections.TryRemove(nameServer, out _);
                    }

                    //cleanup unused tls connections
                    foreach (NameServerAddress nameServer in _existingTlsConnections.Keys.ToArray())
                    {
                        ConcurrentDictionary<object, TlsClientConnection> existingTlsConnection = _existingTlsConnections[nameServer];

                        foreach (object proxy in existingTlsConnection.Keys.ToArray())
                        {
                            TlsClientConnection connection = existingTlsConnection[proxy];

                            if (connection.LastQueried < expiryTime)
                                existingTlsConnection.TryRemove(proxy, out _);
                        }

                        if (existingTlsConnection.IsEmpty)
                            _existingTlsConnections.TryRemove(nameServer, out _);
                    }
                }
                catch
                { }
            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_PERIODIC_INTERVAL);
        }

        protected DnsClientConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
        {
            _protocol = protocol;
            _server = server;
            _proxy = proxy;
        }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        { }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region static

        public static DnsClientConnection GetConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
        {
            switch (protocol)
            {
                case DnsTransportProtocol.Udp:
                    return new UdpClientConnection(server, proxy);

                case DnsTransportProtocol.Https:
                    return new HttpsClientConnection(server, proxy);

                case DnsTransportProtocol.HttpsJson:
                    return new HttpsJsonClientConnection(server, proxy);

                case DnsTransportProtocol.Tcp:
                    {
                        ConcurrentDictionary<object, TcpClientConnection> existingTcpConnection = _existingTcpConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<object, TcpClientConnection>();
                        });

                        object proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NO_PROXY;

                        return existingTcpConnection.GetOrAdd(proxyKey, delegate (object netProxyKey)
                        {
                            TcpClientConnection connection = new TcpClientConnection(server, proxy);
                            connection.SetPooled();
                            return connection;
                        });
                    }

                case DnsTransportProtocol.Tls:
                    {
                        ConcurrentDictionary<object, TlsClientConnection> existingTlsConnection = _existingTlsConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<object, TlsClientConnection>();
                        });

                        object proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NO_PROXY;

                        return existingTlsConnection.GetOrAdd(proxyKey, delegate (object netProxyKey)
                        {
                            TlsClientConnection connection = new TlsClientConnection(server, proxy);
                            connection.SetPooled();
                            return connection;
                        });
                    }

                default:
                    throw new NotSupportedException("DnsClient protocol not supported: " + protocol.ToString());
            }
        }

        #endregion

        #region public

        public abstract DnsDatagram Query(DnsDatagram request, int timeout);

        #endregion

        #region properties

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public NameServerAddress Server
        { get { return _server; } }

        public NetProxy NetProxy
        { get { return _proxy; } }

        #endregion
    }
}
