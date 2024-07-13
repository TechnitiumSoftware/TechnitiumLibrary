/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksProxyUdpAssociateHandler : IProxyServerUdpAssociateHandler, IDisposable
    {
        #region variables

        readonly Socket _controlSocket;
        readonly Socket _udpSocket;
        EndPoint _relayEP;

        #endregion

        #region constructor

        internal SocksProxyUdpAssociateHandler(Socket controlSocket, Socket udpSocket, EndPoint relayEP)
        {
            _controlSocket = controlSocket;
            _udpSocket = udpSocket;
            _relayEP = relayEP;

            if (_relayEP.GetPort() == 0)
                _relayEP = null; //no relay ep provided

            _ = ReadControlSocketAsync();
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;
        readonly object _disposeLock = new object();

        protected virtual void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_controlSocket != null)
                    {
                        try
                        {
                            if (_controlSocket.Connected)
                                _controlSocket.Shutdown(SocketShutdown.Both);
                        }
                        catch
                        { }

                        _controlSocket.Dispose();
                    }

                    if (_udpSocket != null)
                        _udpSocket.Dispose();
                }

                _disposed = true;
            }
        }

        #endregion

        #region private

        private async Task ReadControlSocketAsync()
        {
            try
            {
                byte[] buffer = new byte[128];
                int bytesRecv;

                while (true)
                {
                    bytesRecv = await _controlSocket.ReceiveAsync(buffer, SocketFlags.None);
                    if (bytesRecv < 1)
                        break;
                }
            }
            finally
            {
                Dispose();
            }
        }

        #endregion

        #region public

        public Task<int> SendToAsync(ArraySegment<byte> buffer, EndPoint remoteEP, CancellationToken cancellationToken = default)
        {
            if (_relayEP == null)
                return Task.FromResult(0); //relay ep not known yet

            //get type, address bytes & port bytes
            SocksAddressType type;
            byte[] address;
            ushort port;

            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        type = SocksAddressType.IPv4Address;

                        IPEndPoint ep = remoteEP as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        type = SocksAddressType.IPv6Address;

                        IPEndPoint ep = remoteEP as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.Unspecified:
                    {
                        type = SocksAddressType.DomainName;

                        DomainEndPoint ep = remoteEP as DomainEndPoint;
                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            //create datagram
            byte[] datagram = new byte[address.Length + 6 + buffer.Count];

            datagram[2] = 0x00;
            datagram[3] = (byte)type;

            Buffer.BlockCopy(address, 0, datagram, 4, address.Length);

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);
            Buffer.BlockCopy(portBytes, 0, datagram, 4 + address.Length, 2);

            buffer.CopyTo(datagram, 4 + address.Length + 2);

            //send datagram
            return _udpSocket.SendToAsync(datagram, SocketFlags.None, _relayEP, cancellationToken).AsTask();
        }

        public async Task<SocketReceiveFromResult> ReceiveFromAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] datagram = new byte[262 + buffer.Count];

            SocketReceiveFromResult result = await _udpSocket.ReceiveFromAsync(datagram, SocketFlags.None, SocketExtensions.GetEndPointAnyFor(_udpSocket.AddressFamily), cancellationToken);

            if (result.ReceivedBytes < 10)
                throw new SocksProxyException("Incomplete SOCKS5 datagram was received.");

            EndPoint remoteEP;

            switch ((SocksAddressType)datagram[3])
            {
                case SocksAddressType.IPv4Address:
                    {
                        byte[] address = new byte[4];
                        Buffer.BlockCopy(datagram, 3 + 1, address, 0, 4);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(datagram, 3 + 1 + 4, port, 0, 2);
                        Array.Reverse(port);

                        remoteEP = new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }
                    break;

                case SocksAddressType.IPv6Address:
                    {
                        byte[] address = new byte[16];
                        Buffer.BlockCopy(datagram, 3 + 1, address, 0, 16);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(datagram, 3 + 1 + 16, port, 0, 2);
                        Array.Reverse(port);

                        remoteEP = new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }
                    break;

                case SocksAddressType.DomainName:
                    {
                        int length = datagram[3 + 1];

                        byte[] address = new byte[length];
                        Buffer.BlockCopy(datagram, 3 + 1 + 1, address, 0, length);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(datagram, 3 + 1 + 1 + length, port, 0, 2);
                        Array.Reverse(port);

                        remoteEP = new DomainEndPoint(Encoding.ASCII.GetString(address), BitConverter.ToUInt16(port, 0));
                    }
                    break;

                default:
                    throw new NotSupportedException("SocksAddressType not supported.");
            }

            int addressSize;

            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    addressSize = 4;
                    break;

                case AddressFamily.InterNetworkV6:
                    addressSize = 16;
                    break;

                case AddressFamily.Unspecified:
                    addressSize = 1 + (remoteEP as DomainEndPoint).Address.Length;
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            int dataOffset = 6 + addressSize;
            int dataSize = result.ReceivedBytes - dataOffset;

            if (dataSize > buffer.Count)
                dataSize = buffer.Count;

            ArraySegment<byte> recvData = new ArraySegment<byte>(datagram, dataOffset, dataSize);
            recvData.CopyTo(buffer);

            if (_relayEP == null)
                _relayEP = result.RemoteEndPoint; //set new relay ep

            return new SocketReceiveFromResult() { ReceivedBytes = dataSize, RemoteEndPoint = remoteEP };
        }

        public async Task<int> UdpQueryAsync(ArraySegment<byte> request, ArraySegment<byte> response, EndPoint remoteEP, int timeout = 10000, int retries = 1, bool expBackoffTimeout = false, Func<int, bool> isResponseValid = null, CancellationToken cancellationToken = default)
        {
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
                await SendToAsync(request, remoteEP, cancellationToken);

                while (true)
                {
                    //receive with timeout
                    Task<SocketReceiveFromResult> recvTask;

                    using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                    {
                        await using (CancellationTokenRegistration ctr = cancellationToken.Register(cancellationTokenSource.Cancel))
                        {
                            CancellationToken currentCancellationToken = cancellationTokenSource.Token;

                            recvTask = ReceiveFromAsync(response, currentCancellationToken);

                            if (await Task.WhenAny(recvTask, Task.Delay(timeoutValue, currentCancellationToken)) != recvTask)
                            {
                                cancellationTokenSource.Cancel(); //to stop recv task
                                break; //recv timed out
                            }

                            cancellationTokenSource.Cancel(); //to stop delay task
                        }
                    }

                    SocketReceiveFromResult result = await recvTask;

                    if (((remoteEP is DomainEndPoint) || remoteEP.Equals(result.RemoteEndPoint)) && ((isResponseValid is null) || isResponseValid(result.ReceivedBytes))) //in case remoteEP is domain end point then returned response will contain the resolved IP address so cant compare it together
                    {
                        //got response
                        return result.ReceivedBytes;
                    }
                }
            }

            throw new SocketException((int)SocketError.TimedOut);
        }

        #endregion

        #region properties

        public bool ProxyConnected
        { get { return _controlSocket.Connected; } }

        public EndPoint ProxyUdpRelayEndPoint
        { get { return _relayEP; } }

        #endregion
    }
}
