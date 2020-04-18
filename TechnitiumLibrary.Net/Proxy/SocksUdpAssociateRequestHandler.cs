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

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksUdpAssociateRequestHandler : IDisposable
    {
        #region variables

        readonly Socket _controlSocket;
        readonly Socket _udpSocket;
        readonly EndPoint _relayEP;

        readonly Thread _watchThread;

        #endregion

        #region constructor

        internal SocksUdpAssociateRequestHandler(Socket controlSocket, Socket udpSocket, EndPoint relayEP)
        {
            _controlSocket = controlSocket;
            _udpSocket = udpSocket;
            _relayEP = relayEP;

            _watchThread = new Thread(delegate (object state)
            {
                try
                {
                    byte[] buffer = new byte[128];
                    int bytesRecv;

                    while (true)
                    {
                        bytesRecv = _controlSocket.Receive(buffer);
                        if (bytesRecv < 1)
                            break;
                    }

                    this.Dispose();
                }
                catch (ObjectDisposedException)
                { }
                catch
                {
                    this.Dispose();
                }
            });

            _watchThread.IsBackground = true;
            _watchThread.Start();
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
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
                        _controlSocket.Shutdown(SocketShutdown.Both);
                        _controlSocket.Dispose();
                    }

                    if (_udpSocket != null)
                    {
                        _udpSocket.Shutdown(SocketShutdown.Both);
                        _udpSocket.Dispose();
                    }
                }

                _disposed = true;
            }
        }

        #endregion

        #region private

        private static byte[] CreateUdpDatagram(byte[] buffer, int offset, int size, EndPoint dstAddr)
        {
            //get type, address bytes & port bytes
            SocksAddressType type;
            byte[] address;
            ushort port;

            switch (dstAddr.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        type = SocksAddressType.IPv4Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        type = SocksAddressType.IPv6Address;

                        IPEndPoint ep = dstAddr as IPEndPoint;
                        address = ep.Address.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                case AddressFamily.Unspecified:
                    {
                        type = SocksAddressType.DomainName;

                        DomainEndPoint ep = dstAddr as DomainEndPoint;
                        address = ep.GetAddressBytes();
                        port = Convert.ToUInt16(ep.Port);
                    }
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            //create datagram
            byte[] datagram = new byte[address.Length + 6 + size];

            datagram[2] = 0x00;
            datagram[3] = (byte)type;

            Buffer.BlockCopy(address, 0, datagram, 4, address.Length);

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);
            Buffer.BlockCopy(portBytes, 0, datagram, 4 + address.Length, 2);

            Buffer.BlockCopy(buffer, offset, datagram, 4 + address.Length + 2, size);

            return datagram;
        }

        #endregion

        #region public

        public void SendTo(byte[] buffer, int offset, int size, EndPoint remoteEP)
        {
            byte[] datagram = CreateUdpDatagram(buffer, offset, size, remoteEP);

            _udpSocket.SendTo(datagram, _relayEP);
        }

        public int ReceiveFrom(byte[] buffer, int offset, int size, out EndPoint remoteEP)
        {
            byte[] datagram = new byte[262 + size];
            EndPoint dummyEP = new IPEndPoint(IPAddress.Any, 0);

            int bytesReceived = _udpSocket.ReceiveFrom(datagram, 0, datagram.Length, SocketFlags.None, ref dummyEP);

            if (bytesReceived < 10)
                throw new SocksProxyException("The connection was reset by the remote peer.");

            remoteEP = SocksProxy.ParseEndpoint(datagram, 3);

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
            int dataSize = bytesReceived - dataOffset;

            if (dataSize > size)
                dataSize = size;

            Buffer.BlockCopy(datagram, dataOffset, buffer, offset, dataSize);

            return dataSize;
        }

        #endregion

        #region properties

        public bool ProxyConnected
        { get { return _controlSocket.Connected; } }

        public EndPoint ProxyUdpRelayEndPoint
        { get { return _relayEP; } }

        public int ReceiveTimeout
        {
            get { return _udpSocket.ReceiveTimeout; }
            set { _udpSocket.ReceiveTimeout = value; }
        }

        #endregion
    }
}
