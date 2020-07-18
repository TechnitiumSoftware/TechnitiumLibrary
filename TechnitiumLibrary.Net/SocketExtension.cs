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
            if (ep.AddressFamily == AddressFamily.Unspecified)
                ep = ep.GetIPEndPoint();

            IAsyncResult result = socket.BeginConnect(ep, null, null);

            if (!result.AsyncWaitHandle.WaitOne(timeout))
            {
                socket.Dispose();
                throw new SocketException((int)SocketError.TimedOut);
            }

            socket.EndConnect(result);
        }

        public static Task SendToAsync(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags, EndPoint remoteEP)
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

        public static Task<ReceiveFromResult> ReceiveFromAsync(this Socket socket, byte[] buffer, int offset, int size, SocketFlags socketFlags)
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
                    return new ReceiveFromResult(bytesReceived, ep);
                },
                null);
        }

        public static Task ConnectAsync(this Socket socket, string host, int port)
        {
            return Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, host, port, null);
        }

        public static Task ConnectAsync(this Socket socket, IPAddress address, int port)
        {
            return Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, address, port, null);
        }

        public static Task ConnectAsync(this Socket socket, EndPoint ep)
        {
            return Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, ep, null);
        }

        public static async void ConnectAsync(this Socket socket, string host, int port, int timeout)
        {
            Task task = Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, host, port, null);

            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                if (await Task.WhenAny(new Task[] { task, Task.Delay(timeout, cancellationTokenSource.Token) }) != task)
                {
                    socket.Dispose();
                    throw new SocketException((int)SocketError.TimedOut);
                }

                cancellationTokenSource.Cancel(); //to stop delay task
            }

            await task; //await again for any exception to be rethrown
        }

        public static void ConnectAsync(this Socket socket, IPAddress address, int port, int timeout)
        {
            ConnectAsync(socket, new IPEndPoint(address, port), timeout);
        }

        public static async void ConnectAsync(this Socket socket, EndPoint ep, int timeout)
        {
            Task task = Task.Factory.FromAsync(socket.BeginConnect, socket.EndConnect, ep, null);

            using (var cancellationTokenSource = new CancellationTokenSource())
            {
                if (await Task.WhenAny(new Task[] { task, Task.Delay(timeout, cancellationTokenSource.Token) }) != task)
                {
                    socket.Dispose();
                    throw new SocketException((int)SocketError.TimedOut);
                }

                cancellationTokenSource.Cancel(); //to stop delay task
            }

            await task; //await again for any exception to be rethrown
        }

        #endregion
    }

    public class ReceiveFromResult
    {
        #region variables

        readonly int _bytesReceived;
        readonly EndPoint _remoteEP;

        #endregion

        #region constructor

        public ReceiveFromResult(int bytesReceived, EndPoint remoteEP)
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
