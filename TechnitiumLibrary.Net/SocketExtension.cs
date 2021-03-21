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

        #region private

        internal static IPEndPoint GetEndPointAnyFor(AddressFamily addressFamily)
        {
            switch (addressFamily)
            {
                case AddressFamily.InterNetwork:
                    return IPEndPointAny;

                case AddressFamily.InterNetworkV6:
                    return IPEndPointIPv6Any;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

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

        public static async Task<int> UdpQueryAsync(this Socket socket, ArraySegment<byte> request, ArraySegment<byte> response, EndPoint remoteEP, int timeout = 2000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default)
        {
            Task<SocketReceiveFromResult> recvTask = null;
            EndPoint epAny = GetEndPointAnyFor(remoteEP.AddressFamily);

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
                await socket.SendToAsync(request, SocketFlags.None, remoteEP);

                while (true)
                {
                    //receive request
                    if (recvTask == null)
                        recvTask = socket.ReceiveFromAsync(response, SocketFlags.None, epAny);

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

                    SocketReceiveFromResult result = await recvTask;

                    if (remoteEP.Equals(result.RemoteEndPoint))
                    {
                        //got response
                        return result.ReceivedBytes;
                    }

                    //recv task is complete; set recvTask to null so that another task is used to read next response packet
                    recvTask = null;
                }
            }

            socket.Dispose();
            throw new SocketException((int)SocketError.TimedOut);
        }

        public static async Task CopyToAsync(this Socket src, Socket dst, int bufferSize = 64 * 1024)
        {
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while (true)
            {
                bytesRead = await src.ReceiveAsync(buffer, SocketFlags.None);
                if (bytesRead < 1)
                    break;

                await dst.SendAsync(new ArraySegment<byte>(buffer, 0, bytesRead), SocketFlags.None);
            }
        }

        public static async Task PipeToAsync(this Socket socket1, Socket socket2, int bufferSize = 64 * 1024)
        {
            Task t1 = socket1.CopyToAsync(socket2, bufferSize).ContinueWith(delegate (Task prevTask)
            {
                if ((prevTask.Status == TaskStatus.RanToCompletion) && socket2.Connected)
                    socket2.Shutdown(SocketShutdown.Send);
            });

            Task t2 = socket2.CopyToAsync(socket1, bufferSize).ContinueWith(delegate (Task prevTask)
            {
                if ((prevTask.Status == TaskStatus.RanToCompletion) && socket1.Connected)
                    socket1.Shutdown(SocketShutdown.Send);
            });

            await Task.WhenAll(t1, t2);
        }

        #endregion
    }
}
