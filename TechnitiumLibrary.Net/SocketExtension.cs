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
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net
{
    public static class SocketExtension
    {
        #region variables

        readonly static IPEndPoint IPEndPointAny = new IPEndPoint(IPAddress.Any, 0);
        readonly static IPEndPoint IPEndPointIPv6Any = new IPEndPoint(IPAddress.IPv6Any, 0);

        #endregion

        #region static

        public static void Connect(this Socket socket, string host, int port, int timeout)
        {
            IAsyncResult result = socket.BeginConnect(host, port, null, null);

            if (!result.AsyncWaitHandle.WaitOne(timeout))
            {
                socket.Dispose();
                throw new SocketException((int)SocketError.TimedOut);
            }

            socket.EndConnect(result);
        }

        public static void Connect(this Socket socket, IPAddress address, int port, int timeout)
        {
            Connect(socket, new IPEndPoint(address, port), timeout);
        }

        public static void Connect(this Socket socket, EndPoint ep, int timeout)
        {
            IAsyncResult result = socket.BeginConnect(ep, null, null);

            if (!result.AsyncWaitHandle.WaitOne(timeout))
            {
                socket.Dispose();
                throw new SocketException((int)SocketError.TimedOut);
            }

            socket.EndConnect(result);
        }

        public static Task<int> SendToAsync(this Socket socket, byte[] buffer, EndPoint remoteEP)
        {
            return SendToAsync(socket, buffer, 0, buffer.Length, remoteEP);
        }

        public static Task<int> SendToAsync(this Socket socket, byte[] buffer, int offset, int size, EndPoint remoteEP, SocketFlags socketFlags = SocketFlags.None)
        {
            return Task.Factory.FromAsync(
                delegate (AsyncCallback callback, object state)
                {
                    return socket.BeginSendTo(buffer, offset, size, socketFlags, remoteEP, callback, state);
                },
                delegate (IAsyncResult result)
                {
                    return socket.EndSendTo(result);
                },
                null);
        }

        public static Task<UdpReceiveFromResult> ReceiveFromAsync(this Socket socket, byte[] buffer)
        {
            return ReceiveFromAsync(socket, buffer, 0, buffer.Length);
        }

        public static Task<UdpReceiveFromResult> ReceiveFromAsync(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags = SocketFlags.None)
        {
            return Task.Factory.FromAsync(
                delegate (AsyncCallback callback, object state)
                {
                    EndPoint ep;

                    if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                        ep = IPEndPointIPv6Any;
                    else
                        ep = IPEndPointAny;

                    return socket.BeginReceiveFrom(buffer, offset, size, socketFlags, ref ep, callback, state);
                },
                delegate (IAsyncResult result)
                {
                    EndPoint ep;

                    if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                        ep = IPEndPointIPv6Any;
                    else
                        ep = IPEndPointAny;

                    int bytesReceived = socket.EndReceiveFrom(result, ref ep);
                    return new UdpReceiveFromResult(bytesReceived, ep);
                },
                null);
        }

        public static Task<int> UdpQueryAsync(this Socket socket, byte[] request, byte[] response, EndPoint remoteEP, int timeout = 2000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default)
        {
            return UdpQueryAsync(socket, request, 0, request.Length, response, 0, response.Length, remoteEP, timeout, retries, expBackoffTimeout, cancellationToken);
        }

        public static async Task<int> UdpQueryAsync(this Socket socket, byte[] request, int requestOffset, int requestCount, byte[] response, int responseOffset, int responseCount, EndPoint remoteEP, int timeout = 2000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default)
        {
            Task<UdpReceiveFromResult> recvTask = null;

            int timeoutValue = timeout;
            int retry = 0;
            while (retry < retries) //retry loop
            {
                if (expBackoffTimeout)
                    timeoutValue = timeout * (2 ^ retry);

                retry++;

                if (cancellationToken.IsCancellationRequested)
                    return await Task.FromCanceled<int>(cancellationToken); //task cancelled

                //send request
                await socket.SendToAsync(request, requestOffset, requestCount, remoteEP);

                //receive request
                if (recvTask == null)
                    recvTask = socket.ReceiveFromAsync(response, responseOffset, responseCount);

                while (true)
                {
                    //receive with timeout
                    using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
                    {
                        using (CancellationTokenRegistration ctr = cancellationToken.Register(delegate () { timeoutCancellationTokenSource.Cancel(); }))
                        {
                            if (await Task.WhenAny(recvTask, Task.Delay(timeoutValue, timeoutCancellationTokenSource.Token)) != recvTask)
                                break; //recv timed out
                        }

                        timeoutCancellationTokenSource.Cancel(); //to stop delay task
                    }

                    var result = await recvTask;

                    if (remoteEP.Equals(result.RemoteEndPoint))
                    {
                        //got response
                        return result.BytesReceived;
                    }
                }
            }

            socket.Dispose();
            throw new SocketException((int)SocketError.TimedOut);
        }

        public static Task<int> SendAsync(this Socket socket, byte[] buffer)
        {
            return SendAsync(socket, buffer, 0, buffer.Length);
        }

        public static Task<int> SendAsync(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags = SocketFlags.None)
        {
            return Task.Factory.FromAsync(
                delegate (AsyncCallback callback, object state)
                {
                    return socket.BeginSend(buffer, offset, size, socketFlags, callback, state);
                },
                delegate (IAsyncResult result)
                {
                    return socket.EndSend(result);
                },
                null);
        }

        public static Task<int> ReceiveAsync(this Socket socket, byte[] buffer)
        {
            return ReceiveAsync(socket, buffer, 0, buffer.Length);
        }

        public static Task<int> ReceiveAsync(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags = SocketFlags.None)
        {
            return Task.Factory.FromAsync(
                delegate (AsyncCallback callback, object state)
                {
                    return socket.BeginReceive(buffer, offset, size, socketFlags, callback, state);
                },
                delegate (IAsyncResult result)
                {
                    return socket.EndReceive(result);
                },
                null);
        }

        public static async Task CopyToAsync(this Socket src, Socket dst)
        {
            byte[] buffer = new byte[8 * 1024];
            int bytesRead;

            while (true)
            {
                bytesRead = await src.ReceiveAsync(buffer, 0, buffer.Length);
                if (bytesRead < 1)
                    break;

                await dst.SendAsync(buffer, 0, bytesRead);
            }

            if (dst.Connected)
                dst.Shutdown(SocketShutdown.Both);
        }

        #endregion
    }

    public class UdpReceiveFromResult
    {
        #region variables

        readonly int _bytesReceived;
        readonly EndPoint _remoteEP;

        #endregion

        #region constructor

        public UdpReceiveFromResult(int bytesReceived, EndPoint remoteEP)
        {
            _bytesReceived = bytesReceived;
            _remoteEP = remoteEP;
        }

        #endregion

        #region properties

        public int BytesReceived
        { get { return _bytesReceived; } }

        public EndPoint RemoteEndPoint
        { get { return _remoteEP; } }

        #endregion
    }
}
