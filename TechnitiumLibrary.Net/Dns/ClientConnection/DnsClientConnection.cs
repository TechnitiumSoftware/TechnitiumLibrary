/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
    public abstract class DnsClientConnection : IDisposable, IAsyncDisposable
    {
        #region variables

        protected const int SOL_SOCKET = 1;
        protected const int SO_BINDTODEVICE = 25;

        readonly static Timer _maintenanceTimer;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = CONNECTION_EXPIRY;
        const int MAINTENANCE_TIMER_PERIODIC_INTERVAL = CONNECTION_EXPIRY;
        const int CONNECTION_EXPIRY = 15 * 60 * 1000;

        protected readonly NameServerAddress _server;
        protected readonly NetProxy _proxy;

        static IReadOnlyList<NetworkAddress> _ipv4SourceAddresses;
        static IReadOnlyList<NetworkAddress> _ipv6SourceAddresses;
        static List<Tuple<IPEndPoint, byte[]>> _ipv4SourceEPs;
        static List<Tuple<IPEndPoint, byte[]>> _ipv6SourceEPs;

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

        protected DnsClientConnection(NameServerAddress server, NetProxy proxy)
        {
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
                EDnsClientSubnetOptionData responseECS = response.GetEDnsClientSubnetOption();
                if (requestECS is null)
                {
                    if (responseECS is not null)
                        response.ShadowHideEDnsClientSubnetOption(); //hide unexpected ECS in response
                }
                else
                {
                    if (responseECS is not null)
                    {
                        if (requestECS.Family != responseECS.Family)
                        {
                            if (response.IsReferrerResponse())
                                response.ShadowHideEDnsClientSubnetOption();
                            else
                                throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch (address family).");
                        }
                        else if (requestECS.SourcePrefixLength != responseECS.SourcePrefixLength)
                        {
                            if (response.IsReferrerResponse())
                                response.ShadowHideEDnsClientSubnetOption();
                            else
                                throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch (source prefix).");
                        }
                        else if (!requestECS.Address.Equals(responseECS.Address))
                        {
                            if (response.IsReferrerResponse())
                                response.ShadowHideEDnsClientSubnetOption();
                            else
                                throw new DnsClientResponseValidationException("Invalid response was received: EDNS Client Subnet mismatch (address).");
                        }
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

            if (response.Identifier != request.Identifier)
                throw new DnsClientResponseSpoofedException("Invalid response was received: query ID mismatch."); //possible spoof attempt for UDP transport since QNAME, QTYPE, QCLASS & ECS match but ID does not match
        }

        protected static Tuple<IPEndPoint, byte[]> GetIPv4SourceEP()
        {
            if (_ipv4SourceEPs is null)
                return null;

            switch (_ipv4SourceEPs.Count)
            {
                case 0:
                    return null;

                case 1:
                    return _ipv4SourceEPs[0];

                default:
                    return _ipv4SourceEPs[RandomNumberGenerator.GetInt32(0, _ipv4SourceEPs.Count)];
            }
        }

        protected static Tuple<IPEndPoint, byte[]> GetIPv6SourceEP()
        {
            if (_ipv6SourceEPs is null)
                return null;

            switch (_ipv6SourceEPs.Count)
            {
                case 0:
                    return null;

                case 1:
                    return _ipv6SourceEPs[0];

                default:
                    return _ipv6SourceEPs[RandomNumberGenerator.GetInt32(0, _ipv6SourceEPs.Count)];
            }
        }

        #endregion

        #region private

        private static void FindEndPointsFor(NetworkAddress networkAddress, List<Tuple<IPEndPoint, byte[]>> endPoints)
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                foreach (UnicastIPAddressInformation ip in nic.GetIPProperties().UnicastAddresses)
                {
                    if (networkAddress.Contains(ip.Address))
                    {
                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            endPoints.Add(new Tuple<IPEndPoint, byte[]>(new IPEndPoint(ip.Address, 0), Encoding.ASCII.GetBytes(nic.Name)));
                        else
                            endPoints.Add(new Tuple<IPEndPoint, byte[]>(new IPEndPoint(ip.Address, 0), null));

                        if (networkAddress.IsHostAddress)
                            return;
                    }
                }
            }
        }

        #endregion

        #region public

        public abstract Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken);

        #endregion

        #region properties

        public NameServerAddress Server
        { get { return _server; } }

        public NetProxy NetProxy
        { get { return _proxy; } }

        public static IReadOnlyList<NetworkAddress> IPv4SourceAddresses
        {
            get
            {
                if (_ipv4SourceAddresses is null)
                    _ipv4SourceAddresses = new NetworkAddress[] { new NetworkAddress(IPAddress.Any, 32) };

                return _ipv4SourceAddresses;
            }
            set
            {
                if ((value is null) || (value.Count == 0) || ((value.Count == 1) && value[0].Address.Equals(IPAddress.Any) && value[0].IsHostAddress))
                {
                    if (_ipv4SourceEPs is null)
                        return; //prevent socket pool recreation

                    _ipv4SourceAddresses = null;
                    _ipv4SourceEPs = null;
                }
                else
                {
                    if (value.Count > byte.MaxValue)
                        throw new ArgumentOutOfRangeException(nameof(IPv4SourceAddresses), "Networks cannot be more than 255.");

                    if (value.HasSameItems(_ipv4SourceAddresses))
                        return; //prevent socket pool recreation

                    List<Tuple<IPEndPoint, byte[]>> ipv4SourceEPs = new List<Tuple<IPEndPoint, byte[]>>(value.Count);

                    foreach (NetworkAddress networkAddress in value)
                    {
                        if (networkAddress.AddressFamily != AddressFamily.InterNetwork)
                            throw new ArgumentException("Source address must be an IPv4 address.", nameof(IPv4SourceAddresses));

                        FindEndPointsFor(networkAddress, ipv4SourceEPs);
                    }

                    _ipv4SourceAddresses = value;
                    _ipv4SourceEPs = ipv4SourceEPs;
                }

                UdpClientConnection.ReCreateSocketPoolIPv4();
            }
        }

        public static IReadOnlyList<NetworkAddress> IPv6SourceAddresses
        {
            get
            {
                if (_ipv6SourceAddresses is null)
                    _ipv6SourceAddresses = new NetworkAddress[] { new NetworkAddress(IPAddress.IPv6Any, 128) };

                return _ipv6SourceAddresses;
            }
            set
            {
                if ((value is null) || (value.Count == 0) || ((value.Count == 1) && value[0].Address.Equals(IPAddress.IPv6Any) && value[0].IsHostAddress))
                {
                    if (_ipv6SourceEPs is null)
                        return; //prevent socket pool recreation

                    _ipv6SourceAddresses = null;
                    _ipv6SourceEPs = null;
                }
                else
                {
                    if (value.Count > byte.MaxValue)
                        throw new ArgumentOutOfRangeException(nameof(IPv6SourceAddresses), "Networks cannot be more than 255.");

                    if (value.HasSameItems(_ipv6SourceAddresses))
                        return; //prevent socket pool recreation

                    List<Tuple<IPEndPoint, byte[]>> ipv6SourceEPs = new List<Tuple<IPEndPoint, byte[]>>(value.Count);

                    foreach (NetworkAddress networkAddress in value)
                    {
                        if (networkAddress.AddressFamily != AddressFamily.InterNetworkV6)
                            throw new ArgumentException("Source address must be an IPv6 address.", nameof(IPv6SourceAddresses));

                        FindEndPointsFor(networkAddress, ipv6SourceEPs);
                    }

                    _ipv6SourceAddresses = value;
                    _ipv6SourceEPs = ipv6SourceEPs;
                }

                UdpClientConnection.ReCreateSocketPoolIPv6();
            }
        }

        #endregion
    }
}
