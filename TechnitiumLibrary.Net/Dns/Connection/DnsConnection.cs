/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.Connection
{
    public abstract class DnsConnection : IDisposable
    {
        #region variables

        protected readonly DnsClientProtocol _protocol;
        protected readonly NameServerAddress _server;
        protected readonly NetProxy _proxy;

        protected int _timeout;

        static ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, DnsConnection>> _existingTcpConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, DnsConnection>>();
        static ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, DnsConnection>> _existingTlsConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, DnsConnection>>();

        #endregion

        #region constructor

        protected DnsConnection(DnsClientProtocol protocol, NameServerAddress server, NetProxy proxy)
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

        public static DnsConnection GetConnection(DnsClientProtocol protocol, NameServerAddress server, NetProxy proxy)
        {
            switch (protocol)
            {
                case DnsClientProtocol.Udp:
                    return new UdpConnection(server, proxy);

                case DnsClientProtocol.Https:
                    return new HttpsConnection(server, proxy);

                case DnsClientProtocol.HttpsJson:
                    return new HttpsJsonConnection(server, proxy);

                case DnsClientProtocol.Tcp:
                    {
                        ConcurrentDictionary<NetProxy, DnsConnection> existingTcpConnection = _existingTcpConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, DnsConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NetProxy.None;

                        return existingTcpConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            return new TcpConnection(server, proxy);
                        });
                    }

                case DnsClientProtocol.Tls:
                    {
                        ConcurrentDictionary<NetProxy, DnsConnection> existingTlsConnection = _existingTlsConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, DnsConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NetProxy.None;

                        return existingTlsConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            return new TlsConnection(server, proxy);
                        });
                    }

                default:
                    throw new NotSupportedException("DnsClient protocol not supported: " + protocol.ToString());
            }
        }

        #endregion

        #region public

        public abstract DnsDatagram Query(DnsDatagram request);

        #endregion

        #region properties

        public DnsClientProtocol Protocol
        { get { return _protocol; } }

        public NameServerAddress Server
        { get { return _server; } }

        public NetProxy NetProxy
        { get { return _proxy; } }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        #endregion
    }
}
