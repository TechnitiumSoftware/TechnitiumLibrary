/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public abstract class DnsClientConnection : IDisposable, IAsyncDisposable
    {
        #region variables

        readonly static Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = CONNECTION_EXPIRY;
        const int MAINTENANCE_TIMER_PERIODIC_INTERVAL = CONNECTION_EXPIRY;
        const int CONNECTION_EXPIRY = 15 * 60 * 1000;

        protected readonly DnsTransportProtocol _protocol;
        protected readonly NameServerAddress _server;
        protected readonly NetProxy _proxy;

        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, TcpClientConnection>> _existingTcpConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, TcpClientConnection>>();
        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, TlsClientConnection>> _existingTlsConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, TlsClientConnection>>();
        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, HttpsClientConnection>> _existingHttpsConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, HttpsClientConnection>>();
        static readonly ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, QuicClientConnection>> _existingQuicConnections = new ConcurrentDictionary<NameServerAddress, ConcurrentDictionary<NetProxy, QuicClientConnection>>();

        #endregion

        #region constructor

        static DnsClientConnection()
        {
            _maintenanceTimer = new Timer(async delegate (object state)
            {
                try
                {
                    DateTime expiryTime = DateTime.UtcNow.AddMilliseconds(CONNECTION_EXPIRY * -1);

                    //cleanup unused tcp connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, TcpClientConnection>> existingTcpConnection in _existingTcpConnections)
                    {
                        foreach (KeyValuePair<NetProxy, TcpClientConnection> connection in existingTcpConnection.Value)
                        {
                            if (connection.Value.LastQueried < expiryTime)
                            {
                                if (existingTcpConnection.Value.TryRemove(connection.Key, out TcpClientConnection removedConnection))
                                {
                                    removedConnection.Pooled = false;
                                    removedConnection.Dispose();
                                }
                            }
                        }

                        if (existingTcpConnection.Value.IsEmpty)
                            _existingTcpConnections.TryRemove(existingTcpConnection.Key, out _);
                    }

                    //cleanup unused tls connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, TlsClientConnection>> existingTlsConnection in _existingTlsConnections)
                    {
                        foreach (KeyValuePair<NetProxy, TlsClientConnection> connection in existingTlsConnection.Value)
                        {
                            if (connection.Value.LastQueried < expiryTime)
                            {
                                if (existingTlsConnection.Value.TryRemove(connection.Key, out TlsClientConnection removedConnection))
                                {
                                    removedConnection.Pooled = false;
                                    removedConnection.Dispose();
                                }
                            }
                        }

                        if (existingTlsConnection.Value.IsEmpty)
                            _existingTlsConnections.TryRemove(existingTlsConnection.Key, out _);
                    }

                    //cleanup unused https connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, HttpsClientConnection>> existingHttpsConnection in _existingHttpsConnections)
                    {
                        foreach (KeyValuePair<NetProxy, HttpsClientConnection> connection in existingHttpsConnection.Value)
                        {
                            if (connection.Value.LastQueried < expiryTime)
                            {
                                if (existingHttpsConnection.Value.TryRemove(connection.Key, out HttpsClientConnection removedConnection))
                                {
                                    removedConnection.Pooled = false;
                                    removedConnection.Dispose();
                                }
                            }
                        }

                        if (existingHttpsConnection.Value.IsEmpty)
                            _existingHttpsConnections.TryRemove(existingHttpsConnection.Key, out _);
                    }

                    //cleanup unused quic connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, QuicClientConnection>> existingQuicConnection in _existingQuicConnections)
                    {
                        foreach (KeyValuePair<NetProxy, QuicClientConnection> connection in existingQuicConnection.Value)
                        {
                            if (connection.Value.LastQueried < expiryTime)
                            {
                                if (existingQuicConnection.Value.TryRemove(connection.Key, out QuicClientConnection removedConnection))
                                {
                                    removedConnection.Pooled = false;
                                    await removedConnection.DisposeAsync();
                                }
                            }
                        }

                        if (existingQuicConnection.Value.IsEmpty)
                            _existingQuicConnections.TryRemove(existingQuicConnection.Key, out _);
                    }
                }
                catch
                { }
            });

            _maintenanceTimer.Change(MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_PERIODIC_INTERVAL);
        }

        protected DnsClientConnection(DnsTransportProtocol protocol, NameServerAddress server, NetProxy proxy)
        {
            _protocol = protocol;
            _server = server;
            _proxy = proxy;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        { }

        protected virtual ValueTask DisposeAsyncCore()
        {
            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            Dispose(true);
            GC.SuppressFinalize(this);

            _disposed = true;
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            await DisposeAsyncCore();
            Dispose(false);
            GC.SuppressFinalize(this);

            _disposed = true;
        }

        #endregion

        #region static

        public static DnsClientConnection GetConnection(NameServerAddress server, NetProxy proxy)
        {
            switch (server.Protocol)
            {
                case DnsTransportProtocol.Udp:
                    return new UdpClientConnection(server, proxy);

                case DnsTransportProtocol.Tcp:
                    {
                        ConcurrentDictionary<NetProxy, TcpClientConnection> existingTcpConnection = _existingTcpConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, TcpClientConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey is null)
                            proxyKey = NetProxy.NONE;

                        return existingTcpConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            TcpClientConnection connection = new TcpClientConnection(server, proxy);
                            connection.Pooled = true;
                            return connection;
                        });
                    }

                case DnsTransportProtocol.Tls:
                    {
                        ConcurrentDictionary<NetProxy, TlsClientConnection> existingTlsConnection = _existingTlsConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, TlsClientConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey is null)
                            proxyKey = NetProxy.NONE;

                        return existingTlsConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            TlsClientConnection connection = new TlsClientConnection(server, proxy);
                            connection.Pooled = true;
                            return connection;
                        });
                    }

                case DnsTransportProtocol.Https:
                    {
                        ConcurrentDictionary<NetProxy, HttpsClientConnection> existingHttpsConnection = _existingHttpsConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, HttpsClientConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey is null)
                            proxyKey = NetProxy.NONE;

                        return existingHttpsConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            HttpsClientConnection connection = new HttpsClientConnection(server, proxy);
                            connection.Pooled = true;
                            return connection;
                        });
                    }

                case DnsTransportProtocol.Quic:
                    {
                        ConcurrentDictionary<NetProxy, QuicClientConnection> existingQuicConnection = _existingQuicConnections.GetOrAdd(server, delegate (NameServerAddress nameServer)
                        {
                            return new ConcurrentDictionary<NetProxy, QuicClientConnection>();
                        });

                        NetProxy proxyKey = proxy;

                        if (proxyKey is null)
                            proxyKey = NetProxy.NONE;

                        return existingQuicConnection.GetOrAdd(proxyKey, delegate (NetProxy netProxyKey)
                        {
                            QuicClientConnection connection = new QuicClientConnection(server, proxy);
                            connection.Pooled = true;
                            return connection;
                        });
                    }

                default:
                    throw new NotSupportedException("DnsClient protocol not supported: " + server.Protocol.ToString());
            }
        }

        #endregion

        #region protected

        protected static void ValidateResponse(DnsDatagram request, DnsDatagram response)
        {
            if (response.Identifier != request.Identifier)
                throw new DnsClientResponseValidationException("Invalid response was received: query ID mismatch.");

            if (response.Question.Count == request.Question.Count)
            {
                for (int i = 0; i < response.Question.Count; i++)
                {
                    if (request.Question[i].ZoneCut is null)
                    {
                        if (!response.Question[i].Name.Equals(request.Question[i].Name, StringComparison.Ordinal))
                            throw new DnsClientResponseValidationException("Invalid response was received: QNAME mismatch.");

                        if (response.Question[i].Type != request.Question[i].Type)
                            throw new DnsClientResponseValidationException("Invalid response was received: QTYPE mismatch.");
                    }
                    else
                    {
                        if (!response.Question[i].Name.Equals(request.Question[i].MinimizedName, StringComparison.Ordinal))
                            throw new DnsClientResponseValidationException("Invalid response was received: QNAME mismatch.");

                        if (response.Question[i].Type != request.Question[i].MinimizedType)
                            throw new DnsClientResponseValidationException("Invalid response was received: QTYPE mismatch.");
                    }

                    if (response.Question[i].Class != request.Question[i].Class)
                        throw new DnsClientResponseValidationException("Invalid response was received: QCLASS mismatch.");
                }

                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                {
                    EDnsClientSubnetOptionData responseECS = response.GetEDnsClientSubnetOption();
                    if (responseECS is not null)
                    {
                        if (requestECS.Family != responseECS.Family)
                            throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch.");

                        if (requestECS.SourcePrefixLength != responseECS.SourcePrefixLength)
                            throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch.");

                        if (!requestECS.Address.Equals(responseECS.Address))
                            throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch.");
                    }
                }
            }
            else
            {
                switch (response.RCODE)
                {
                    case DnsResponseCode.FormatError:
                    case DnsResponseCode.Refused:
                        break;

                    default:
                        throw new DnsClientResponseValidationException("Invalid response was received: question count mismatch.");
                }
            }
        }

        #endregion

        #region public

        public abstract Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken);

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
