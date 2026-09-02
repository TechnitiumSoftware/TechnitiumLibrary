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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ClientConnection
{
#pragma warning disable CA1416 // Validate platform compatibility

    public enum DnsOverQuicErrorCodes : long
    {
        /// <summary>
        /// No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
        /// </summary>
        DOQ_NO_ERROR = 0,

        /// <summary>
        /// The DoQ implementation encountered an internal error and is incapable of pursuing the transaction or the connection.
        /// </summary>
        DOQ_INTERNAL_ERROR = 1,

        /// <summary>
        /// The DoQ implementation encountered a protocol error and is forcibly aborting the connection.
        /// </summary>
        DOQ_PROTOCOL_ERROR = 2,

        /// <summary>
        /// A DoQ client uses this to signal that it wants to cancel an outstanding transaction.
        /// </summary>
        DOQ_REQUEST_CANCELLED = 3,

        /// <summary>
        /// A DoQ implementation uses this to signal when closing a connection due to excessive load.
        /// </summary>
        DOQ_EXCESSIVE_LOAD = 4,

        /// <summary>
        /// A DoQ implementation uses this in the absence of a more specific error code.
        /// </summary>
        DOQ_UNSPECIFIED_ERROR = 5,

        /// <summary>
        /// An alternative error code used for tests.
        /// </summary>
        DOQ_ERROR_RESERVED = 0xd098ea5e
    }

    public class QuicClientConnection : DnsClientConnection
    {
        #region variables

        QuicConnection _quicConnection;
        UdpTunnelProxy _udpTunnelProxy;

        bool _pooled;
        DateTime _lastQueried;

        readonly SemaphoreSlim _connectionSemaphore = new SemaphoreSlim(1, 1);
        readonly ConditionalWeakTable<QuicConnection, SemaphoreSlim> _streamCapacitySemaphores = new ConditionalWeakTable<QuicConnection, SemaphoreSlim>();
        readonly ConditionalWeakTable<QuicConnection, Task> _connectionRetirementTasks = new ConditionalWeakTable<QuicConnection, Task>();
        readonly ConcurrentDictionary<Task, CancellationTokenSource> _lateTasks = new ConcurrentDictionary<Task, CancellationTokenSource>();
        readonly ConcurrentDictionary<Task, byte> _retirementTasks = new ConcurrentDictionary<Task, byte>();
        readonly ConcurrentQueue<Exception> _retirementFailures = new ConcurrentQueue<Exception>();
        readonly CancellationTokenSource _stoppingCancellationTokenSource = new CancellationTokenSource();
        readonly TaskCompletionSource _activeQueriesDrained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        int _stopping;
        int _queryAdmissionState;

        const int QUERY_ADMISSION_CLOSED = int.MinValue;
        const int ACTIVE_QUERY_COUNT_MASK = int.MaxValue;

        #endregion

        #region constructor

        public QuicClientConnection(NameServerAddress server, NetProxy proxy)
            : base(server, proxy)
        {
            if (server.Protocol != DnsTransportProtocol.Quic)
                throw new ArgumentException("Name server protocol does not match.", nameof(server));
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_pooled)
                CompleteDisposeAsync(StopAndCloseQueryAdmission()).GetAwaiter().GetResult();
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            if (!_pooled)
                await CompleteDisposeAsync(StopAndCloseQueryAdmission()).ConfigureAwait(false);
        }

        private async Task CompleteDisposeAsync(Task activeQueriesDrained)
        {
            try
            {
                try
                {
                    await DisposeConnectionAsync(Interlocked.Exchange(ref _quicConnection, null)).ConfigureAwait(false);
                }
                finally
                {
                    try
                    {
                        await activeQueriesDrained.ConfigureAwait(false);
                    }
                    finally
                    {
                        try
                        {
                            await DrainLateTasksAsync().ConfigureAwait(false);
                        }
                        finally
                        {
                            try
                            {
                                await DrainRetirementTasksAsync().ConfigureAwait(false);
                            }
                            finally
                            {
                                await DisposeConnectionAsync(Interlocked.Exchange(ref _quicConnection, null)).ConfigureAwait(false);
                            }
                        }
                    }
                }
            }
            finally
            {
                Interlocked.Exchange(ref _udpTunnelProxy, null)?.Dispose();
            }
        }

        #endregion

        #region private

        private static async ValueTask DisposeConnectionAsync(QuicConnection quicConnection)
        {
            if (quicConnection is null)
                return;

            try
            {
                await quicConnection.CloseAsync(0).ConfigureAwait(false);
            }
            finally
            {
                await quicConnection.DisposeAsync().ConfigureAwait(false);
            }
        }

        private void StartQuery()
        {
            while (true)
            {
                int admissionState = Volatile.Read(ref _queryAdmissionState);

                if ((admissionState & QUERY_ADMISSION_CLOSED) != 0)
                    throw new ObjectDisposedException(nameof(QuicClientConnection));

                if ((admissionState & ACTIVE_QUERY_COUNT_MASK) == ACTIVE_QUERY_COUNT_MASK)
                    throw new InvalidOperationException("The active QUIC query count overflowed.");

                if (Interlocked.CompareExchange(ref _queryAdmissionState, admissionState + 1, admissionState) == admissionState)
                    return;
            }
        }

        private void FinishQuery()
        {
            while (true)
            {
                int admissionState = Volatile.Read(ref _queryAdmissionState);
                int activeQueryCount = admissionState & ACTIVE_QUERY_COUNT_MASK;

                if (activeQueryCount == 0)
                    throw new InvalidOperationException("The active QUIC query count is invalid.");

                int newAdmissionState = admissionState - 1;
                if (Interlocked.CompareExchange(ref _queryAdmissionState, newAdmissionState, admissionState) != admissionState)
                    continue;

                if (((newAdmissionState & QUERY_ADMISSION_CLOSED) != 0) && ((newAdmissionState & ACTIVE_QUERY_COUNT_MASK) == 0))
                    _activeQueriesDrained.TrySetResult();

                return;
            }
        }

        private Task StopAndCloseQueryAdmission()
        {
            Interlocked.Exchange(ref _stopping, 1);

            try
            {
                _stoppingCancellationTokenSource.Cancel();
            }
            catch (AggregateException ex)
            {
                Debug.WriteLine(ex);
            }

            while (true)
            {
                int admissionState = Volatile.Read(ref _queryAdmissionState);

                if ((admissionState & QUERY_ADMISSION_CLOSED) != 0)
                    break;

                int closedAdmissionState = admissionState | QUERY_ADMISSION_CLOSED;
                if (Interlocked.CompareExchange(ref _queryAdmissionState, closedAdmissionState, admissionState) == admissionState)
                    break;
            }

            if ((Volatile.Read(ref _queryAdmissionState) & ACTIVE_QUERY_COUNT_MASK) == 0)
                _activeQueriesDrained.TrySetResult();

            return _activeQueriesDrained.Task;
        }

        private static async Task DisposeInvalidatedConnectionAsync(QuicConnection quicConnection, UdpTunnelProxy udpTunnelProxy)
        {
            try
            {
                await quicConnection.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                udpTunnelProxy?.Dispose();
            }
        }

        private static async Task CompleteInvalidatedConnectionAsync(QuicConnection quicConnection, UdpTunnelProxy udpTunnelProxy, TaskCompletionSource retirementCompleted)
        {
            try
            {
                await DisposeInvalidatedConnectionAsync(quicConnection, udpTunnelProxy).ConfigureAwait(false);
                retirementCompleted.TrySetResult();
            }
            catch (Exception ex)
            {
                retirementCompleted.TrySetException(ex);
            }
        }

        private async ValueTask<bool> AwaitRetirementAsync(Task retirementTask, long deadline, CancellationToken cancellationToken, CancellationToken waitCancellationToken)
        {
            bool retirementCompleted = await WaitForTaskAsync(retirementTask, GetRemainingTimeout(deadline), waitCancellationToken).ConfigureAwait(false);

            if (cancellationToken.IsCancellationRequested)
            {
                TrackRetirementTask(retirementTask);
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (!retirementCompleted)
            {
                TrackRetirementTask(retirementTask);
                return false;
            }

            await retirementTask.ConfigureAwait(false);
            return true;
        }

        private async ValueTask<bool> InvalidateConnectionAsync(QuicConnection quicConnection, int timeout, CancellationToken cancellationToken)
        {
            long invalidationDeadline = GetQueryDeadline(timeout, 1);
            using CancellationTokenSource invalidationCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stoppingCancellationTokenSource.Token);

            if (!ReferenceEquals(Volatile.Read(ref _quicConnection), quicConnection))
            {
                if (_connectionRetirementTasks.TryGetValue(quicConnection, out Task existingRetirementTask))
                    return await AwaitRetirementAsync(existingRetirementTask, invalidationDeadline, cancellationToken, invalidationCancellationTokenSource.Token).ConfigureAwait(false);

                return true;
            }

            bool semaphoreAcquired;

            try
            {
                semaphoreAcquired = await _connectionSemaphore.WaitAsync(GetRemainingTimeout(invalidationDeadline), invalidationCancellationTokenSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw;
            }

            if (!semaphoreAcquired)
                return false;

            Task retirementTask;

            try
            {
                if (!ReferenceEquals(Volatile.Read(ref _quicConnection), quicConnection))
                {
                    if (!_connectionRetirementTasks.TryGetValue(quicConnection, out retirementTask))
                        return true;
                }
                else
                {
                    TaskCompletionSource retirementCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    retirementTask = retirementCompleted.Task;
                    _connectionRetirementTasks.Add(quicConnection, retirementTask);

                    Volatile.Write(ref _quicConnection, null);
                    UdpTunnelProxy udpTunnelProxy = Interlocked.Exchange(ref _udpTunnelProxy, null);
                    _ = CompleteInvalidatedConnectionAsync(quicConnection, udpTunnelProxy, retirementCompleted);
                }
            }
            finally
            {
                _connectionSemaphore.Release();
            }

            return await AwaitRetirementAsync(retirementTask, invalidationDeadline, cancellationToken, invalidationCancellationTokenSource.Token).ConfigureAwait(false);
        }

        private async Task ObserveRetirementTaskAsync(Task task)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _retirementFailures.Enqueue(ex);
                ReportRetirementFailure(ex);
            }
            finally
            {
                _retirementTasks.TryRemove(task, out _);
            }
        }

        private void TrackRetirementTask(Task task)
        {
            if (!_retirementTasks.TryAdd(task, 0))
                return;

            _ = ObserveRetirementTaskAsync(task);
        }

        private async Task DrainRetirementTasksAsync()
        {
            while (!_retirementTasks.IsEmpty)
            {
                foreach (Task retirementTask in _retirementTasks.Keys)
                {
                    try
                    {
                        await retirementTask.ConfigureAwait(false);
                    }
                    catch
                    { }
                }
            }

            if (!_retirementFailures.IsEmpty)
            {
                List<Exception> retirementFailures = new List<Exception>();

                while (_retirementFailures.TryDequeue(out Exception retirementFailure))
                    retirementFailures.Add(retirementFailure);

                throw new AggregateException("One or more QUIC connection retirements failed.", retirementFailures);
            }
        }

        private static void ReportRetirementFailure(Exception exception)
        {
            try
            {
                Console.Error.WriteLine("QUIC connection retirement failed: " + exception);
            }
            catch
            { }
        }

        private async Task ObserveLateTaskAsync(Task task)
        {
            try
            {
                await task;
            }
            catch (OperationCanceledException)
            { }
            catch (ObjectDisposedException)
            { }
            catch (QuicException)
            { }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
            finally
            {
                if (_lateTasks.TryRemove(task, out CancellationTokenSource cancellationTokenSource))
                    cancellationTokenSource.Dispose();
            }
        }

        private void TrackLateTask(Task task, CancellationTokenSource cancellationTokenSource)
        {
            if (!_lateTasks.TryAdd(task, cancellationTokenSource))
                throw new InvalidOperationException("The late QUIC task is already tracked.");

            _ = ObserveLateTaskAsync(task);
        }

        private async Task DrainLateTasksAsync()
        {
            while (!_lateTasks.IsEmpty)
            {
                foreach (KeyValuePair<Task, CancellationTokenSource> lateTask in _lateTasks)
                {
                    try
                    {
                        await lateTask.Key;
                    }
                    catch (OperationCanceledException)
                    { }
                    catch (ObjectDisposedException)
                    { }
                    catch (QuicException)
                    { }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex);
                    }

                    if (_lateTasks.TryRemove(lateTask.Key, out CancellationTokenSource cancellationTokenSource))
                        cancellationTokenSource.Dispose();
                }
            }
        }

        private static async Task ObserveTaskAsync(Task task)
        {
            try
            {
                await task;
            }
            catch (OperationCanceledException)
            { }
            catch (ObjectDisposedException)
            { }
            catch (QuicException)
            { }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private static async Task<bool> WaitForTaskAsync(Task task, int timeout, CancellationToken cancellationToken)
        {
            using (CancellationTokenSource delayCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                try
                {
                    Task completedTask = await Task.WhenAny(task, Task.Delay(timeout, delayCancellationTokenSource.Token));
                    return completedTask == task;
                }
                finally
                {
                    delayCancellationTokenSource.Cancel();
                }
            }
        }

        private static long GetQueryDeadline(int timeout, long attempts)
        {
            if (timeout == Timeout.Infinite)
                return long.MaxValue;

            long now = Environment.TickCount64;
            attempts = Math.Max(attempts, 1L);

            if (timeout <= 0)
                return now;

            if (attempts > (long.MaxValue - now) / timeout)
                return long.MaxValue;

            return now + (timeout * attempts);
        }

        private static int GetRemainingTimeout(long deadline)
        {
            if (deadline == long.MaxValue)
                return Timeout.Infinite;

            long remaining = deadline - Environment.TickCount64;

            if (remaining <= 0)
                return 0;

            return remaining > int.MaxValue ? int.MaxValue : Convert.ToInt32(remaining);
        }

        private static int GetShorterTimeout(int firstTimeout, int secondTimeout)
        {
            if (firstTimeout == Timeout.Infinite)
                return secondTimeout;

            if (secondTimeout == Timeout.Infinite)
                return firstTimeout;

            return Math.Min(firstTimeout, secondTimeout);
        }

        private static void AbortCancelledStream(object state)
        {
            try
            {
                ((QuicStream)state).Abort(QuicAbortDirection.Both, (long)DnsOverQuicErrorCodes.DOQ_REQUEST_CANCELLED);
            }
            catch (ObjectDisposedException)
            { }
            catch (QuicException)
            { }
        }

        private SemaphoreSlim GetStreamCapacitySemaphore(QuicConnection quicConnection)
        {
            return _streamCapacitySemaphores.GetValue(quicConnection, static delegate { return new SemaphoreSlim(0); });
        }

        private void OnStreamCapacityChanged(QuicConnection quicConnection, QuicStreamCapacityChangedArgs args)
        {
            if (args.BidirectionalIncrement <= 0)
                return;

            try
            {
                GetStreamCapacitySemaphore(quicConnection).Release(args.BidirectionalIncrement);
            }
            catch (SemaphoreFullException ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private async Task<QuicConnection> GetConnectionAsync(int timeout, CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _stopping) != 0)
                throw new ObjectDisposedException(nameof(QuicClientConnection));

            QuicConnection existingConnection = Volatile.Read(ref _quicConnection);
            if (existingConnection is not null)
                return existingConnection;

            if (!await _connectionSemaphore.WaitAsync(timeout, cancellationToken))
                return null; //timed out

            try
            {
                existingConnection = Volatile.Read(ref _quicConnection);
                if (existingConnection is not null)
                    return existingConnection;

                if (Volatile.Read(ref _stopping) != 0)
                    throw new ObjectDisposedException(nameof(QuicClientConnection));

                IPEndPoint remoteEP;

                if (_proxy is null)
                {
                    if (_server.IsIPEndPointStale)
                        await _server.RecursiveResolveIPAddressAsync(cancellationToken: cancellationToken);

                    remoteEP = _server.IPEndPoint;
                }
                else
                {
                    if (!await _proxy.IsUdpAvailableAsync(cancellationToken))
                        throw new DnsClientException("Unable to connect: The configured proxy server does not support UDP transport required by QUIC protocol.");

                    if ((_udpTunnelProxy is null) || _udpTunnelProxy.IsBroken)
                        _udpTunnelProxy = await _proxy.CreateUdpTunnelProxyAsync(_server.EndPoint, cancellationToken);

                    remoteEP = _udpTunnelProxy.TunnelEndPoint;
                }

                QuicClientConnectionOptions connectionOptions = new QuicClientConnectionOptions()
                {
                    RemoteEndPoint = remoteEP,
                    DefaultCloseErrorCode = (long)DnsOverQuicErrorCodes.DOQ_NO_ERROR,
                    DefaultStreamErrorCode = (long)DnsOverQuicErrorCodes.DOQ_REQUEST_CANCELLED,
                    MaxInboundUnidirectionalStreams = 0,
                    MaxInboundBidirectionalStreams = 0,
                    StreamCapacityCallback = OnStreamCapacityChanged,
                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        ApplicationProtocols = new List<SslApplicationProtocol>() { new SslApplicationProtocol("doq") },
                        TargetHost = _server.Host
                    }
                };

                if (_proxy is null)
                {
                    switch (remoteEP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            Tuple<IPEndPoint, byte[]> ipv4SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv4SourceEP();
                            if (ipv4SourceEP is not null)
                                connectionOptions.LocalEndPoint = ipv4SourceEP.Item1;

                            break;

                        case AddressFamily.InterNetworkV6:
                            Tuple<IPEndPoint, byte[]> ipv6SourceEP = IPAddress.IsLoopback(remoteEP.Address) ? null : GetIPv6SourceEP();
                            if (ipv6SourceEP is not null)
                                connectionOptions.LocalEndPoint = ipv6SourceEP.Item1;

                            break;
                    }
                }

                using CancellationTokenSource connectCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCancellationTokenSource.CancelAfter(30000);

                QuicConnection newConnection;

                try
                {
                    newConnection = await QuicConnection.ConnectAsync(connectionOptions, connectCancellationTokenSource.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && connectCancellationTokenSource.IsCancellationRequested)
                {
                    throw new TimeoutException();
                }

                if (Volatile.Read(ref _stopping) != 0)
                {
                    await DisposeConnectionAsync(newConnection).ConfigureAwait(false);
                    throw new ObjectDisposedException(nameof(QuicClientConnection));
                }

                Volatile.Write(ref _quicConnection, newConnection);

                if (Volatile.Read(ref _stopping) != 0)
                {
                    if (ReferenceEquals(Interlocked.CompareExchange(ref _quicConnection, null, newConnection), newConnection))
                        await DisposeConnectionAsync(newConnection).ConfigureAwait(false);

                    throw new ObjectDisposedException(nameof(QuicClientConnection));
                }

                return newConnection;
            }
            finally
            {
                _connectionSemaphore.Release();

                if (Volatile.Read(ref _stopping) != 0)
                    Interlocked.Exchange(ref _udpTunnelProxy, null)?.Dispose();
            }
        }

        private async Task<DnsDatagram> QuicQueryAsync(DnsDatagram request, QuicConnection quicConnection, CancellationToken cancellationToken)
        {
            SemaphoreSlim streamCapacitySemaphore = GetStreamCapacitySemaphore(quicConnection);
            await streamCapacitySemaphore.WaitAsync(cancellationToken);

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                streamCapacitySemaphore.Release();
                throw;
            }

            await using (QuicStream quicStream = await quicConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, CancellationToken.None))
            {
                await using CancellationTokenRegistration cancellationTokenRegistration = cancellationToken.Register(AbortCancelledStream, quicStream);

                cancellationToken.ThrowIfCancellationRequested();

                //serialize and send request with FIN flag
                using (MemoryStream mS = new MemoryStream(64))
                {
                    mS.Position = 2;
                    request.WriteTo(mS);

                    long datagramLength = mS.Length - 2L;
                    if (datagramLength > ushort.MaxValue)
                        throw new InvalidOperationException();

                    mS.Position = 0;
                    DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(datagramLength), mS);
                    mS.Position = 0;

                    //write with FIN
                    await quicStream.WriteAsync(mS.GetBuffer().AsMemory(0, (int)mS.Length), true, cancellationToken);
                }

                if ((request.Question.Count > 0) && (request.Question[0].Type == DnsResourceRecordType.AXFR))
                {
                    //read zone transfer response
                    DnsDatagram firstResponse = null;
                    DnsDatagram lastResponse = null;
                    MemoryStream sharedBuffer = new MemoryStream(4096);
                    bool isFirstResponse = false;

                    while (true)
                    {
                        DnsDatagram response = await DnsDatagram.ReadFromTcpAsync(quicStream, sharedBuffer, cancellationToken);

                        if (firstResponse is null)
                        {
                            firstResponse = response;
                            isFirstResponse = true;
                        }
                        else
                        {
                            lastResponse.NextDatagram = response;
                        }

                        lastResponse = response;

                        if ((response.Answer.Count == 0) || ((response.Answer[response.Answer.Count - 1].Type == DnsResourceRecordType.SOA) && ((response.Answer.Count > 1) || !isFirstResponse)))
                            break;
                    }

                    return firstResponse;
                }
                else
                {
                    //read standard response
                    return await DnsDatagram.ReadFromTcpAsync(quicStream, 512, cancellationToken);
                }
            }
        }

        #endregion

        #region public

        public override async Task<DnsDatagram> QueryAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            StartQuery();

            try
            {
                Task<DnsDatagram> queryTask;

                if ((SynchronizationContext.Current is null) && (TaskScheduler.Current == TaskScheduler.Default))
                {
                    queryTask = QueryCoreAsync(request, timeout, retries, cancellationToken);
                }
                else
                {
                    queryTask = Task.Run(delegate { return QueryCoreAsync(request, timeout, retries, cancellationToken); });
                }

                return await queryTask.ConfigureAwait(false);
            }
            finally
            {
                FinishQuery();
            }
        }

        private async Task<DnsDatagram> QueryCoreAsync(DnsDatagram request, int timeout, int retries, CancellationToken cancellationToken)
        {
            _lastQueried = DateTime.UtcNow;

            Stopwatch stopwatch = new Stopwatch();

            stopwatch.Start();

            long requestDeadline = GetQueryDeadline(timeout, Math.Max((long)retries, 1L) * 2L);
            bool queryDeadlineSet = false;
            long queryDeadline = 0;
            int retry = 0;
            while (retry < retries) //retry loop
            {
                cancellationToken.ThrowIfCancellationRequested();

                retry++;

                int remainingRequestTimeout = GetRemainingTimeout(requestDeadline);
                if (remainingRequestTimeout == 0)
                    break;

                if (queryDeadlineSet)
                {
                    int remainingQueryTimeout = GetRemainingTimeout(queryDeadline);
                    if (remainingQueryTimeout == 0)
                        break;

                    remainingRequestTimeout = GetShorterTimeout(remainingRequestTimeout, remainingQueryTimeout);
                }

                int connectionTimeout = GetShorterTimeout(timeout, remainingRequestTimeout);
                CancellationTokenSource connectionCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stoppingCancellationTokenSource.Token);
                bool connectionCancellationOwnershipTransferred = false;
                Task<QuicConnection> quicConnectionTask = null;
                QuicConnection quicConnection;

                //wait for connection with timeout
                try
                {
                    quicConnectionTask = GetConnectionAsync(connectionTimeout, connectionCancellationTokenSource.Token);

                    if (!await WaitForTaskAsync(quicConnectionTask, connectionTimeout, cancellationToken))
                    {
                        connectionCancellationTokenSource.Cancel();
                        bool connectionCleanupCompleted = quicConnectionTask.IsCompleted;

                        remainingRequestTimeout = GetRemainingTimeout(requestDeadline);
                        if (queryDeadlineSet)
                            remainingRequestTimeout = GetShorterTimeout(remainingRequestTimeout, GetRemainingTimeout(queryDeadline));

                        if (!connectionCleanupCompleted && (remainingRequestTimeout != 0))
                            connectionCleanupCompleted = await WaitForTaskAsync(quicConnectionTask, remainingRequestTimeout, cancellationToken);

                        if (cancellationToken.IsCancellationRequested)
                        {
                            if (connectionCleanupCompleted)
                            {
                                await ObserveTaskAsync(quicConnectionTask);
                            }
                            else
                            {
                                TrackLateTask(quicConnectionTask, connectionCancellationTokenSource);
                                connectionCancellationOwnershipTransferred = true;
                            }

                            cancellationToken.ThrowIfCancellationRequested();
                        }

                        if (!connectionCleanupCompleted)
                        {
                            TrackLateTask(quicConnectionTask, connectionCancellationTokenSource);
                            connectionCancellationOwnershipTransferred = true;
                            break;
                        }

                        await ObserveTaskAsync(quicConnectionTask);
                        continue;
                    }

                    try
                    {
                        quicConnection = await quicConnectionTask;
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        throw;
                    }
                }
                finally
                {
                    if (!connectionCancellationOwnershipTransferred)
                        connectionCancellationTokenSource.Dispose();
                }

                cancellationToken.ThrowIfCancellationRequested();

                if (quicConnection is null)
                    continue; //semaphone wait timed out; retry

                if (!queryDeadlineSet)
                {
                    queryDeadline = GetQueryDeadline(timeout, retries - retry + 1);
                    queryDeadlineSet = true;
                }

                int remainingTimeout = GetRemainingTimeout(queryDeadline);
                if (remainingTimeout == 0)
                    break;

                int attemptTimeout = timeout == Timeout.Infinite ? Timeout.Infinite : Math.Min(timeout, remainingTimeout);
                CancellationTokenSource queryCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stoppingCancellationTokenSource.Token);
                bool queryCancellationOwnershipTransferred = false;
                Task<DnsDatagram> task = null;

                //query and wait for response with timeout
                try
                {
                    task = QuicQueryAsync(request, quicConnection, queryCancellationTokenSource.Token);

                    if (!await WaitForTaskAsync(task, attemptTimeout, cancellationToken))
                    {
                        queryCancellationTokenSource.Cancel();

                        if (cancellationToken.IsCancellationRequested)
                        {
                            if (task.IsCompleted)
                            {
                                await ObserveTaskAsync(task);
                            }
                            else
                            {
                                TrackLateTask(task, queryCancellationTokenSource);
                                queryCancellationOwnershipTransferred = true;
                            }

                            cancellationToken.ThrowIfCancellationRequested();
                        }

                        remainingTimeout = GetRemainingTimeout(queryDeadline);
                        bool queryCleanupCompleted = task.IsCompleted;

                        if (!queryCleanupCompleted && (remainingTimeout != 0))
                            queryCleanupCompleted = await WaitForTaskAsync(task, remainingTimeout, cancellationToken);

                        if (cancellationToken.IsCancellationRequested)
                        {
                            if (queryCleanupCompleted)
                            {
                                await ObserveTaskAsync(task);
                            }
                            else
                            {
                                TrackLateTask(task, queryCancellationTokenSource);
                                queryCancellationOwnershipTransferred = true;
                            }

                            cancellationToken.ThrowIfCancellationRequested();
                        }

                        if (!queryCleanupCompleted)
                        {
                            TrackLateTask(task, queryCancellationTokenSource);
                            queryCancellationOwnershipTransferred = true;
                            break;
                        }

                        await ObserveTaskAsync(task);
                        continue;
                    }

                    DnsDatagram response;

                    try
                    {
                        response = await task;
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        throw;
                    }
                    catch (ObjectDisposedException)
                    {
                        //ensure existing connection is disposed to allow reconnection later
                        int invalidationTimeout = GetShorterTimeout(GetRemainingTimeout(requestDeadline), GetRemainingTimeout(queryDeadline));
                        if (!await InvalidateConnectionAsync(quicConnection, invalidationTimeout, cancellationToken).ConfigureAwait(false))
                            break;

                        if (retry == 1)
                        {
                            //quic connection was disposed on first attempt; retry to reconnect
                            retry = 0;
                            continue;
                        }

                        throw;
                    }
                    catch (QuicException ex)
                    {
                        //close existing connection to allow reconnection later
                        int invalidationTimeout = GetShorterTimeout(GetRemainingTimeout(requestDeadline), GetRemainingTimeout(queryDeadline));
                        if (!await InvalidateConnectionAsync(quicConnection, invalidationTimeout, cancellationToken).ConfigureAwait(false))
                            break;

                        if (((ex.QuicError == QuicError.ConnectionIdle) || (ex.QuicError == QuicError.ConnectionAborted)) && (retry == 1))
                        {
                            //connection idle/aborted on first attempt; retry to reconnect
                            retry = 0;
                            continue;
                        }

                        throw;
                    }

                    cancellationToken.ThrowIfCancellationRequested();

                    stopwatch.Stop();

                    response.SetMetadata(_server, stopwatch.Elapsed.TotalMilliseconds);

                    ValidateResponse(request, response);

                    return response;
                }
                finally
                {
                    if (!queryCancellationOwnershipTransferred)
                        queryCancellationTokenSource.Dispose();
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out for name server [" + _server.ToString() + "].");
        }

        #endregion

        #region properties

        internal DateTime LastQueried
        { get { return _lastQueried; } }

        internal bool Pooled
        {
            get { return _pooled; }
            set { _pooled = value; }
        }

        #endregion
    }

#pragma warning restore CA1416 // Validate platform compatibility
}
