/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

        protected const int IPPROTO_IP = 0;
        protected const int IP_BIND_ADDRESS_NO_PORT = 24;

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

        static readonly ReaderWriterLockSlim _tcpConnectionsLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        static readonly ReaderWriterLockSlim _tlsConnectionsLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        static readonly ReaderWriterLockSlim _httpsConnectionsLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        static readonly ReaderWriterLockSlim _quicConnectionsLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

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
                            TcpClientConnection removedConnection = null;

                            _tcpConnectionsLock.EnterWriteLock();
                            try
                            {
                                if (connection.Value.CanEvictPooledConnection() && (connection.Value.LastQueried < expiryTime))
                                {
                                    if (!existingTcpConnection.Value.TryRemove(connection.Key, out removedConnection) || !ReferenceEquals(removedConnection, connection.Value) || !removedConnection.TryBeginPooledEviction())
                                        throw new InvalidOperationException("Failed to reserve the exact pooled TCP connection for eviction.");
                                }
                            }
                            finally
                            {
                                _tcpConnectionsLock.ExitWriteLock();
                            }

                            if (removedConnection is not null)
                            {
                                try
                                {
                                    await removedConnection.DisposePooledAsync(delegate { removedConnection.Pooled = false; });
                                }
                                catch (Exception ex)
                                {
                                    ReportPoolMaintenanceError(ex);
                                }
                            }
                        }

                        _tcpConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (existingTcpConnection.Value.IsEmpty && _existingTcpConnections.TryGetValue(existingTcpConnection.Key, out ConcurrentDictionary<NetProxy, TcpClientConnection> currentTcpConnections) && ReferenceEquals(currentTcpConnections, existingTcpConnection.Value))
                                _existingTcpConnections.TryRemove(existingTcpConnection.Key, out _);
                        }
                        finally
                        {
                            _tcpConnectionsLock.ExitWriteLock();
                        }
                    }

                    //cleanup unused tls connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, TlsClientConnection>> existingTlsConnection in _existingTlsConnections)
                    {
                        foreach (KeyValuePair<NetProxy, TlsClientConnection> connection in existingTlsConnection.Value)
                        {
                            TlsClientConnection removedConnection = null;

                            _tlsConnectionsLock.EnterWriteLock();
                            try
                            {
                                if (connection.Value.CanEvictPooledConnection() && (connection.Value.LastQueried < expiryTime))
                                {
                                    if (!existingTlsConnection.Value.TryRemove(connection.Key, out removedConnection) || !ReferenceEquals(removedConnection, connection.Value) || !removedConnection.TryBeginPooledEviction())
                                        throw new InvalidOperationException("Failed to reserve the exact pooled TLS connection for eviction.");
                                }
                            }
                            finally
                            {
                                _tlsConnectionsLock.ExitWriteLock();
                            }

                            if (removedConnection is not null)
                            {
                                try
                                {
                                    await removedConnection.DisposePooledAsync(delegate { removedConnection.Pooled = false; });
                                }
                                catch (Exception ex)
                                {
                                    ReportPoolMaintenanceError(ex);
                                }
                            }
                        }

                        _tlsConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (existingTlsConnection.Value.IsEmpty && _existingTlsConnections.TryGetValue(existingTlsConnection.Key, out ConcurrentDictionary<NetProxy, TlsClientConnection> currentTlsConnections) && ReferenceEquals(currentTlsConnections, existingTlsConnection.Value))
                                _existingTlsConnections.TryRemove(existingTlsConnection.Key, out _);
                        }
                        finally
                        {
                            _tlsConnectionsLock.ExitWriteLock();
                        }
                    }

                    //cleanup unused https connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, HttpsClientConnection>> existingHttpsConnection in _existingHttpsConnections)
                    {
                        foreach (KeyValuePair<NetProxy, HttpsClientConnection> connection in existingHttpsConnection.Value)
                        {
                            HttpsClientConnection removedConnection = null;

                            _httpsConnectionsLock.EnterWriteLock();
                            try
                            {
                                if (connection.Value.CanEvictPooledConnection() && (connection.Value.LastQueried < expiryTime))
                                {
                                    if (!existingHttpsConnection.Value.TryRemove(connection.Key, out removedConnection) || !ReferenceEquals(removedConnection, connection.Value) || !removedConnection.TryBeginPooledEviction())
                                        throw new InvalidOperationException("Failed to reserve the exact pooled HTTPS connection for eviction.");
                                }
                            }
                            finally
                            {
                                _httpsConnectionsLock.ExitWriteLock();
                            }

                            if (removedConnection is not null)
                            {
                                try
                                {
                                    await removedConnection.DisposePooledAsync(delegate { removedConnection.Pooled = false; });
                                }
                                catch (Exception ex)
                                {
                                    ReportPoolMaintenanceError(ex);
                                }
                            }
                        }

                        _httpsConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (existingHttpsConnection.Value.IsEmpty && _existingHttpsConnections.TryGetValue(existingHttpsConnection.Key, out ConcurrentDictionary<NetProxy, HttpsClientConnection> currentHttpsConnections) && ReferenceEquals(currentHttpsConnections, existingHttpsConnection.Value))
                                _existingHttpsConnections.TryRemove(existingHttpsConnection.Key, out _);
                        }
                        finally
                        {
                            _httpsConnectionsLock.ExitWriteLock();
                        }
                    }

                    //cleanup unused quic connections
                    foreach (KeyValuePair<NameServerAddress, ConcurrentDictionary<NetProxy, QuicClientConnection>> existingQuicConnection in _existingQuicConnections)
                    {
                        foreach (KeyValuePair<NetProxy, QuicClientConnection> connection in existingQuicConnection.Value)
                        {
                            QuicClientConnection removedConnection = null;

                            _quicConnectionsLock.EnterWriteLock();
                            try
                            {
                                if (connection.Value.CanEvictPooledConnection() && (connection.Value.LastQueried < expiryTime))
                                {
                                    if (!existingQuicConnection.Value.TryRemove(connection.Key, out removedConnection) || !ReferenceEquals(removedConnection, connection.Value) || !removedConnection.TryBeginPooledEviction())
                                        throw new InvalidOperationException("Failed to reserve the exact pooled QUIC connection for eviction.");
                                }
                            }
                            finally
                            {
                                _quicConnectionsLock.ExitWriteLock();
                            }

                            if (removedConnection is not null)
                            {
                                try
                                {
                                    await removedConnection.DisposePooledAsync(delegate { removedConnection.Pooled = false; });
                                }
                                catch (Exception ex)
                                {
                                    ReportPoolMaintenanceError(ex);
                                }
                            }
                        }

                        _quicConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (existingQuicConnection.Value.IsEmpty && _existingQuicConnections.TryGetValue(existingQuicConnection.Key, out ConcurrentDictionary<NetProxy, QuicClientConnection> currentQuicConnections) && ReferenceEquals(currentQuicConnections, existingQuicConnection.Value))
                                _existingQuicConnections.TryRemove(existingQuicConnection.Key, out _);
                        }
                        finally
                        {
                            _quicConnectionsLock.ExitWriteLock();
                        }
                    }
                }
                catch (Exception ex)
                {
                    ReportPoolMaintenanceError(ex);
                }
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

        enum DisposeOperation
        {
            ReleasePooledLease,
            OwnPhysicalDispose,
            JoinPhysicalDispose
        }

        readonly object _disposeLock = new object();

        int _pooledLeaseCount;
        bool _isPooledConnection;
        bool _poolEvictionStarted;
        bool _physicalDisposeStarted;
        TaskCompletionSource _physicalDisposeCompleted;
        Task _physicalDisposeTask;

        protected virtual void Dispose(bool disposing)
        { }

        protected virtual ValueTask DisposeAsyncCore()
        {
            return ValueTask.CompletedTask;
        }

        private bool TryAcquirePooledLease()
        {
            if (Volatile.Read(ref _poolEvictionStarted) || (Volatile.Read(ref _physicalDisposeTask) is not null))
                return false;

            _isPooledConnection = true;

            int leaseCount = Interlocked.Increment(ref _pooledLeaseCount);
            if (leaseCount <= 0)
            {
                Interlocked.Decrement(ref _pooledLeaseCount);
                throw new InvalidOperationException("The pooled DNS connection lease count overflowed.");
            }

            return true;
        }

        private bool CanEvictPooledConnection()
        {
            return Volatile.Read(ref _isPooledConnection) && (Volatile.Read(ref _pooledLeaseCount) == 0) && !Volatile.Read(ref _poolEvictionStarted) && (Volatile.Read(ref _physicalDisposeTask) is null);
        }

        private bool TryBeginPooledEviction()
        {
            lock (_disposeLock)
            {
                if (!_isPooledConnection || (_pooledLeaseCount != 0) || _poolEvictionStarted || (_physicalDisposeTask is not null))
                    return false;

                _poolEvictionStarted = true;
                _physicalDisposeCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _physicalDisposeTask = _physicalDisposeCompleted.Task;
                return true;
            }
        }

        private DisposeOperation BeginDispose(out Task physicalDisposeTask, out TaskCompletionSource physicalDisposeCompleted)
        {
            if (Volatile.Read(ref _isPooledConnection) && !Volatile.Read(ref _poolEvictionStarted))
            {
                int leaseCount = Interlocked.Decrement(ref _pooledLeaseCount);
                if (leaseCount < 0)
                {
                    Interlocked.Increment(ref _pooledLeaseCount);
                    throw new InvalidOperationException("The pooled DNS connection lease count is already zero.");
                }

                physicalDisposeTask = null;
                physicalDisposeCompleted = null;
                return DisposeOperation.ReleasePooledLease;
            }

            lock (_disposeLock)
            {
                if (_physicalDisposeTask is not null)
                {
                    physicalDisposeTask = _physicalDisposeTask;
                    physicalDisposeCompleted = null;
                    return DisposeOperation.JoinPhysicalDispose;
                }

                _physicalDisposeStarted = true;
                _physicalDisposeCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _physicalDisposeTask = _physicalDisposeCompleted.Task;

                physicalDisposeTask = null;
                physicalDisposeCompleted = _physicalDisposeCompleted;
                return DisposeOperation.OwnPhysicalDispose;
            }
        }

        private ValueTask DisposePooledAsync(Action releaseFromPool)
        {
            Task physicalDisposeTask;
            TaskCompletionSource physicalDisposeCompleted;

            lock (_disposeLock)
            {
                if (!_poolEvictionStarted || (_physicalDisposeTask is null) || (_physicalDisposeCompleted is null))
                    throw new InvalidOperationException("The pooled DNS connection was not reserved for eviction.");

                physicalDisposeTask = _physicalDisposeTask;

                if (_physicalDisposeStarted)
                    return new ValueTask(physicalDisposeTask);

                _physicalDisposeStarted = true;
                physicalDisposeCompleted = _physicalDisposeCompleted;
            }

            _ = Task.Run(delegate { return CompletePooledDisposeAsync(releaseFromPool, physicalDisposeCompleted); });
            return new ValueTask(physicalDisposeTask);
        }

        private async Task CompletePooledDisposeAsync(Action releaseFromPool, TaskCompletionSource physicalDisposeCompleted)
        {
            Exception disposeException = null;

            try
            {
                releaseFromPool();
                await DisposeAsyncCore().ConfigureAwait(false);
                Dispose(false);
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                disposeException = ex;
            }
            finally
            {
                CompletePhysicalDispose(physicalDisposeCompleted, disposeException);
            }
        }

        private async Task CompleteDirectDisposeAsync(TaskCompletionSource physicalDisposeCompleted)
        {
            Exception disposeException = null;

            try
            {
                await DisposeAsyncCore().ConfigureAwait(false);
                Dispose(false);
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                disposeException = ex;
            }
            finally
            {
                CompletePhysicalDispose(physicalDisposeCompleted, disposeException);
            }
        }

        private static void CompletePhysicalDispose(TaskCompletionSource physicalDisposeCompleted, Exception disposeException)
        {
            if (disposeException is null)
            {
                physicalDisposeCompleted.TrySetResult();
            }
            else
            {
                physicalDisposeCompleted.TrySetException(disposeException);
                _ = physicalDisposeCompleted.Task.Exception;
            }
        }

        private static void ReportPoolMaintenanceError(Exception exception)
        {
            try
            {
                Console.Error.WriteLine("DNS connection pool maintenance failed: " + exception);
            }
            catch
            { }
        }

        public void Dispose()
        {
            DisposeOperation operation = BeginDispose(out Task physicalDisposeTask, out TaskCompletionSource physicalDisposeCompleted);

            if (operation == DisposeOperation.ReleasePooledLease)
                return;

            if (operation == DisposeOperation.JoinPhysicalDispose)
            {
                physicalDisposeTask.GetAwaiter().GetResult();
                return;
            }

            Exception disposeException = null;

            try
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                disposeException = ex;
                throw;
            }
            finally
            {
                CompletePhysicalDispose(physicalDisposeCompleted, disposeException);
            }
        }

        public async ValueTask DisposeAsync()
        {
            DisposeOperation operation = BeginDispose(out Task physicalDisposeTask, out TaskCompletionSource physicalDisposeCompleted);

            if (operation == DisposeOperation.ReleasePooledLease)
                return;

            if (operation == DisposeOperation.JoinPhysicalDispose)
            {
                await physicalDisposeTask.ConfigureAwait(false);
                return;
            }

            _ = Task.Run(delegate { return CompleteDirectDisposeAsync(physicalDisposeCompleted); });
            await physicalDisposeCompleted.Task.ConfigureAwait(false);
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
                        NetProxy proxyKey = proxy ?? NetProxy.NONE;

                        _tcpConnectionsLock.EnterReadLock();
                        try
                        {
                            if (_existingTcpConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, TcpClientConnection> existingTcpConnection) && existingTcpConnection.TryGetValue(proxyKey, out TcpClientConnection connection))
                            {
                                if (!connection.TryAcquirePooledLease())
                                    throw new InvalidOperationException("Failed to acquire the canonical pooled TCP connection.");

                                return connection;
                            }
                        }
                        finally
                        {
                            _tcpConnectionsLock.ExitReadLock();
                        }

                        _tcpConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (!_existingTcpConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, TcpClientConnection> existingTcpConnection))
                            {
                                existingTcpConnection = new ConcurrentDictionary<NetProxy, TcpClientConnection>();
                                if (!_existingTcpConnections.TryAdd(server, existingTcpConnection))
                                    throw new InvalidOperationException("Failed to add the canonical TCP connection pool.");
                            }

                            if (!existingTcpConnection.TryGetValue(proxyKey, out TcpClientConnection connection))
                            {
                                connection = new TcpClientConnection(server, proxy);
                                connection.Pooled = true;

                                if (!existingTcpConnection.TryAdd(proxyKey, connection))
                                    throw new InvalidOperationException("Failed to add the canonical pooled TCP connection.");
                            }

                            if (!connection.TryAcquirePooledLease())
                                throw new InvalidOperationException("Failed to acquire the canonical pooled TCP connection.");

                            return connection;
                        }
                        finally
                        {
                            _tcpConnectionsLock.ExitWriteLock();
                        }
                    }

                case DnsTransportProtocol.Tls:
                    {
                        NetProxy proxyKey = proxy ?? NetProxy.NONE;

                        _tlsConnectionsLock.EnterReadLock();
                        try
                        {
                            if (_existingTlsConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, TlsClientConnection> existingTlsConnection) && existingTlsConnection.TryGetValue(proxyKey, out TlsClientConnection connection))
                            {
                                if (!connection.TryAcquirePooledLease())
                                    throw new InvalidOperationException("Failed to acquire the canonical pooled TLS connection.");

                                return connection;
                            }
                        }
                        finally
                        {
                            _tlsConnectionsLock.ExitReadLock();
                        }

                        _tlsConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (!_existingTlsConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, TlsClientConnection> existingTlsConnection))
                            {
                                existingTlsConnection = new ConcurrentDictionary<NetProxy, TlsClientConnection>();
                                if (!_existingTlsConnections.TryAdd(server, existingTlsConnection))
                                    throw new InvalidOperationException("Failed to add the canonical TLS connection pool.");
                            }

                            if (!existingTlsConnection.TryGetValue(proxyKey, out TlsClientConnection connection))
                            {
                                connection = new TlsClientConnection(server, proxy);
                                connection.Pooled = true;

                                if (!existingTlsConnection.TryAdd(proxyKey, connection))
                                    throw new InvalidOperationException("Failed to add the canonical pooled TLS connection.");
                            }

                            if (!connection.TryAcquirePooledLease())
                                throw new InvalidOperationException("Failed to acquire the canonical pooled TLS connection.");

                            return connection;
                        }
                        finally
                        {
                            _tlsConnectionsLock.ExitWriteLock();
                        }
                    }

                case DnsTransportProtocol.Https:
                    {
                        NetProxy proxyKey = proxy ?? NetProxy.NONE;

                        _httpsConnectionsLock.EnterReadLock();
                        try
                        {
                            if (_existingHttpsConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, HttpsClientConnection> existingHttpsConnection) && existingHttpsConnection.TryGetValue(proxyKey, out HttpsClientConnection connection))
                            {
                                if (!connection.TryAcquirePooledLease())
                                    throw new InvalidOperationException("Failed to acquire the canonical pooled HTTPS connection.");

                                return connection;
                            }
                        }
                        finally
                        {
                            _httpsConnectionsLock.ExitReadLock();
                        }

                        _httpsConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (!_existingHttpsConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, HttpsClientConnection> existingHttpsConnection))
                            {
                                existingHttpsConnection = new ConcurrentDictionary<NetProxy, HttpsClientConnection>();
                                if (!_existingHttpsConnections.TryAdd(server, existingHttpsConnection))
                                    throw new InvalidOperationException("Failed to add the canonical HTTPS connection pool.");
                            }

                            if (!existingHttpsConnection.TryGetValue(proxyKey, out HttpsClientConnection connection))
                            {
                                connection = new HttpsClientConnection(server, proxy);
                                connection.Pooled = true;

                                if (!existingHttpsConnection.TryAdd(proxyKey, connection))
                                    throw new InvalidOperationException("Failed to add the canonical pooled HTTPS connection.");
                            }

                            if (!connection.TryAcquirePooledLease())
                                throw new InvalidOperationException("Failed to acquire the canonical pooled HTTPS connection.");

                            return connection;
                        }
                        finally
                        {
                            _httpsConnectionsLock.ExitWriteLock();
                        }
                    }

                case DnsTransportProtocol.Quic:
                    {
                        NetProxy proxyKey = proxy ?? NetProxy.NONE;

                        _quicConnectionsLock.EnterReadLock();
                        try
                        {
                            if (_existingQuicConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, QuicClientConnection> existingQuicConnection) && existingQuicConnection.TryGetValue(proxyKey, out QuicClientConnection connection))
                            {
                                if (!connection.TryAcquirePooledLease())
                                    throw new InvalidOperationException("Failed to acquire the canonical pooled QUIC connection.");

                                return connection;
                            }
                        }
                        finally
                        {
                            _quicConnectionsLock.ExitReadLock();
                        }

                        _quicConnectionsLock.EnterWriteLock();
                        try
                        {
                            if (!_existingQuicConnections.TryGetValue(server, out ConcurrentDictionary<NetProxy, QuicClientConnection> existingQuicConnection))
                            {
                                existingQuicConnection = new ConcurrentDictionary<NetProxy, QuicClientConnection>();
                                if (!_existingQuicConnections.TryAdd(server, existingQuicConnection))
                                    throw new InvalidOperationException("Failed to add the canonical QUIC connection pool.");
                            }

                            if (!existingQuicConnection.TryGetValue(proxyKey, out QuicClientConnection connection))
                            {
                                connection = new QuicClientConnection(server, proxy);
                                connection.Pooled = true;

                                if (!existingQuicConnection.TryAdd(proxyKey, connection))
                                    throw new InvalidOperationException("Failed to add the canonical pooled QUIC connection.");
                            }

                            if (!connection.TryAcquirePooledLease())
                                throw new InvalidOperationException("Failed to acquire the canonical pooled QUIC connection.");

                            return connection;
                        }
                        finally
                        {
                            _quicConnectionsLock.ExitWriteLock();
                        }
                    }

                default:
                    throw new NotSupportedException("DnsClient protocol not supported: " + server.Protocol.ToString());
            }
        }

        #endregion

        #region protected

        protected static void ValidateResponse(DnsDatagram request, DnsDatagram response)
        {
            if (!response.IsResponse)
                throw new DnsClientResponseValidationException("Invalid response was received: QR flag not set to response (1).");

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
                        if ((requestECS.Family != responseECS.Family) || (requestECS.SourcePrefixLength != responseECS.SourcePrefixLength) || !requestECS.Address.Equals(responseECS.Address))
                            response.SetShadowEDnsClientSubnetOption(requestECS); //overwrite unexpected ECS in response so that response is cached for 0.0.0.0/0
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
                throw new DnsClientResponseSpoofedException("Invalid response was received: query ID mismatch."); //possible spoof attempt for UDP transport since QNAME, QTYPE, & QCLASS match but ID does not match
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
