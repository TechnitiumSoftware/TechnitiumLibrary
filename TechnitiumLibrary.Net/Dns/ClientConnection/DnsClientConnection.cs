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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public abstract class DnsClientConnection : IDisposable
    {
        #region variables

        protected readonly DnsTransportProtocol _protocol;
        protected readonly NameServerAddress _server;
        protected readonly NetProxy _proxy;

        protected int _timeout;

        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, DnsClientConnection>> _existingTcpConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, DnsClientConnection>>();
        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, DnsClientConnection>> _existingTlsConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<object, DnsClientConnection>>();
        const string NO_PROXY = "NO_PROXY";

        #endregion

        #region constructor

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
                        ConcurrentDictionary<object, DnsClientConnection> existingTcpConnection = _existingTcpConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<object, DnsClientConnection>();
                        });

                        object proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NO_PROXY;

                        return existingTcpConnection.GetOrAdd(proxyKey, delegate (object netProxyKey)
                        {
                            return new TcpClientConnection(server, proxy);
                        });
                    }

                case DnsTransportProtocol.Tls:
                    {
                        ConcurrentDictionary<object, DnsClientConnection> existingTlsConnection = _existingTlsConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<object, DnsClientConnection>();
                        });

                        object proxyKey = proxy;

                        if (proxyKey == null)
                            proxyKey = NO_PROXY;

                        return existingTlsConnection.GetOrAdd(proxyKey, delegate (object netProxyKey)
                        {
                            return new TlsClientConnection(server, proxy);
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

        public DnsTransportProtocol Protocol
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
