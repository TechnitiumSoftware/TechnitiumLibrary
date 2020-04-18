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
using System.Text;

namespace TechnitiumLibrary.Net.Proxy
{
    enum SocksMethod : byte
    {
        NoAuthenticationRequired = 0x0,
        GSSAPI = 0x01,
        UsernamePassword = 0x2,
        NoAcceptableMethods = 0xff
    }

    enum SocksRequestCommand : byte
    {
        Connect = 0x01,
        Bind = 0x02,
        UdpAssociate = 0x03
    }

    public enum SocksReplyCode : byte
    {
        Succeeded = 0x00,
        GeneralSocksServerFailure = 0x01,
        ConnectionNotAllowedByRuleset = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TtlExpired = 0x06,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08
    }

    public enum SocksAddressType : byte
    {
        IPv4Address = 0x01,
        DomainName = 0x03,
        IPv6Address = 0x04
    }

    public class SocksProxy : NetProxy
    {
        #region variables

        public const byte SOCKS_VERSION = 5;

        byte[] _negotiationRequest;
        byte[] _authRequest;

        bool _isUdpAvailableChecked;
        bool _isUdpAvailable;

        #endregion

        #region constructor

        public SocksProxy(EndPoint proxyEP, NetworkCredential credential)
            : base(NetProxyType.Socks5, proxyEP, credential)
        {
            InitCredential();
        }

        #endregion

        #region private

        private void InitCredential()
        {
            if (_credential == null)
            {
                _negotiationRequest = new byte[3];

                _negotiationRequest[0] = SOCKS_VERSION;
                _negotiationRequest[1] = 1; //total methods
                _negotiationRequest[2] = (byte)SocksMethod.NoAuthenticationRequired;
            }
            else
            {
                _negotiationRequest = new byte[4];

                _negotiationRequest[0] = SOCKS_VERSION;
                _negotiationRequest[1] = 2; //total methods
                _negotiationRequest[2] = (byte)SocksMethod.NoAuthenticationRequired;
                _negotiationRequest[3] = (byte)SocksMethod.UsernamePassword;

                _authRequest = new byte[1 + 1 + _credential.UserName.Length + 1 + _credential.Password.Length];

                _authRequest[0] = 0x01;
                _authRequest[1] = Convert.ToByte(_credential.UserName.Length);
                Buffer.BlockCopy(Encoding.ASCII.GetBytes(_credential.UserName), 0, _authRequest, 2, _credential.UserName.Length);
                _authRequest[2 + _credential.UserName.Length] = Convert.ToByte(_credential.Password.Length);
                Buffer.BlockCopy(Encoding.ASCII.GetBytes(_credential.Password), 0, _authRequest, 2 + _credential.UserName.Length + 1, _credential.Password.Length);
            }
        }

        private void Negotiate(Socket socket)
        {
            byte[] response = new byte[2];

            socket.Send(_negotiationRequest);
            if (socket.Receive(response) != 2)
                throw new SocksProxyException("The connection was reset by the remote peer.");

            if (response[0] != SOCKS_VERSION)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            switch ((SocksMethod)response[1])
            {
                case SocksMethod.UsernamePassword:
                    if (_authRequest == null)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server requires authentication.");

                    socket.Send(_authRequest);
                    if (socket.Receive(response) != 2)
                        throw new SocksProxyException("The connection was reset by the remote peer.");

                    if (response[0] != 0x01)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server does not support username/password method version 1.");

                    if (response[1] != 0x00)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server authentication failed: invalid username or password.");

                    break;

                case SocksMethod.NoAuthenticationRequired:
                    break;

                case SocksMethod.NoAcceptableMethods:
                    if (_authRequest == null)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server requires authentication.");
                    else
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server does not support username/password method.");

                default:
                    throw new SocksProxyException("Socks proxy server returned unknown method.");
            }
        }

        private static EndPoint Request(Socket socket, SocksRequestCommand command, EndPoint dstAddr)
        {
            socket.Send(CreateRequest(command, dstAddr));

            byte[] response = new byte[262];

            if (socket.Receive(response) < 10)
                throw new SocksProxyException("The connection was reset by the remote peer.");

            if (response[0] != SOCKS_VERSION)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            SocksReplyCode replyCode = (SocksReplyCode)response[1];

            if (replyCode != SocksReplyCode.Succeeded)
                throw new SocksProxyException("Socks proxy server request failed: " + replyCode.ToString(), replyCode);

            return ParseEndpoint(response, 3);
        }

        internal static EndPoint ParseEndpoint(byte[] buffer, int offset)
        {
            switch ((SocksAddressType)buffer[offset])
            {
                case SocksAddressType.IPv4Address:
                    {
                        byte[] address = new byte[4];
                        Buffer.BlockCopy(buffer, offset + 1, address, 0, 4);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 4, port, 0, 2);
                        Array.Reverse(port);

                        return new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }

                case SocksAddressType.IPv6Address:
                    {
                        byte[] address = new byte[16];
                        Buffer.BlockCopy(buffer, offset + 1, address, 0, 16);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 16, port, 0, 2);
                        Array.Reverse(port);

                        return new IPEndPoint(new IPAddress(address), BitConverter.ToUInt16(port, 0));
                    }

                case SocksAddressType.DomainName:
                    {
                        int length = buffer[offset + 1];

                        byte[] address = new byte[length];
                        Buffer.BlockCopy(buffer, offset + 1 + 1, address, 0, length);

                        byte[] port = new byte[2];
                        Buffer.BlockCopy(buffer, offset + 1 + 1 + length, port, 0, 2);
                        Array.Reverse(port);

                        return new DomainEndPoint(Encoding.ASCII.GetString(address), BitConverter.ToUInt16(port, 0));
                    }

                default:
                    throw new NotSupportedException("SocksAddressType not supported.");
            }
        }

        private static byte[] CreateRequest(SocksRequestCommand command, EndPoint dstAddr)
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

            //create request
            byte[] request = new byte[address.Length + 6];

            request[0] = SOCKS_VERSION;
            request[1] = (byte)command;
            request[3] = (byte)type;

            Buffer.BlockCopy(address, 0, request, 4, address.Length);

            byte[] portBytes = BitConverter.GetBytes(port);
            Array.Reverse(portBytes);
            Buffer.BlockCopy(portBytes, 0, request, 4 + address.Length, 2);

            return request;
        }

        #endregion

        #region protected

        protected override Socket Connect(EndPoint remoteEP, Socket viaSocket)
        {
            try
            {
                Negotiate(viaSocket);
                Request(viaSocket, SocksRequestCommand.Connect, remoteEP);

                return viaSocket;
            }
            catch
            {
                viaSocket.Dispose();
                throw;
            }
        }

        #endregion

        #region public

        public override bool IsProxyAvailable()
        {
            try
            {
                //connect to proxy server
                using (Socket socket = GetTcpConnection(_proxyEP, 5000))
                {
                    socket.SendTimeout = 5000;
                    socket.ReceiveTimeout = 5000;

                    Negotiate(socket);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public override void CheckProxyAccess()
        {
            //connect to proxy server
            using (Socket socket = GetTcpConnection(_proxyEP, 5000))
            {
                socket.SendTimeout = 5000;
                socket.ReceiveTimeout = 5000;

                Negotiate(socket);
            }
        }

        public override bool IsUdpAvailable()
        {
            if (_isUdpAvailableChecked)
                return _isUdpAvailable;

            SocksUdpAssociateRequestHandler udpHandler = null;

            try
            {
                udpHandler = UdpAssociate();

                _isUdpAvailable = true;
            }
            catch (SocksProxyException ex)
            {
                if (ex.ReplyCode == SocksReplyCode.CommandNotSupported)
                    _isUdpAvailable = false;
                else
                    throw;
            }
            finally
            {
                if (udpHandler != null)
                    udpHandler.Dispose();
            }

            _isUdpAvailableChecked = true;

            return _isUdpAvailable;
        }

        public override int UdpReceiveFrom(EndPoint remoteEP, byte[] request, int requestOffset, int requestSize, byte[] response, int responseOffset, int timeout = 10000)
        {
            if (IsBypassed(remoteEP))
            {
                IPEndPoint hostEP = remoteEP.GetIPEndPoint();

                using (Socket socket = new Socket(hostEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.ReceiveTimeout = timeout;

                    //send request
                    socket.SendTo(request, requestOffset, requestSize, SocketFlags.None, hostEP);

                    //receive request
                    EndPoint ep;

                    if (hostEP.AddressFamily == AddressFamily.InterNetworkV6)
                        ep = new IPEndPoint(IPAddress.IPv6Any, 0);
                    else
                        ep = new IPEndPoint(IPAddress.Any, 0);

                    int bytesReceived;

                    do
                    {
                        bytesReceived = socket.ReceiveFrom(response, responseOffset, response.Length, SocketFlags.None, ref ep);
                    }
                    while (!hostEP.Equals(ep));

                    return bytesReceived;
                }
            }

            if (_viaProxy != null)
                throw new NotSupportedException("Cannot chain proxies for Udp protocol.");

            using (SocksUdpAssociateRequestHandler proxyUdpRequestHandler = UdpAssociate(timeout))
            {
                proxyUdpRequestHandler.ReceiveTimeout = timeout;

                //send request
                proxyUdpRequestHandler.SendTo(request, requestOffset, requestSize, remoteEP);

                //receive request
                return proxyUdpRequestHandler.ReceiveFrom(response, responseOffset, response.Length - responseOffset, out EndPoint ep);
            }
        }

        public SocksBindRequestHandler Bind(EndPoint endpoint, int timeout = 30000)
        {
            //connect to proxy server
            Socket socket = GetTcpConnection(_proxyEP, timeout);

            try
            {
                Negotiate(socket);
                EndPoint bindEP = Request(socket, SocksRequestCommand.Bind, endpoint);

                return new SocksBindRequestHandler(socket, bindEP);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(int timeout = 10000)
        {
            return UdpAssociate(new IPEndPoint(IPAddress.Any, 0), timeout);
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(int localPort, int timeout = 10000)
        {
            return UdpAssociate(new IPEndPoint(IPAddress.Any, localPort), timeout);
        }

        public SocksUdpAssociateRequestHandler UdpAssociate(IPEndPoint localEP, int timeout = 10000)
        {
            //bind local ep
            Socket udpSocket = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(localEP);

            //connect to proxy server
            Socket socket = GetTcpConnection(_proxyEP, timeout);

            socket.SendTimeout = 30000;
            socket.ReceiveTimeout = 30000;

            try
            {
                Negotiate(socket);

                EndPoint relayEP = Request(socket, SocksRequestCommand.UdpAssociate, udpSocket.LocalEndPoint);

                return new SocksUdpAssociateRequestHandler(socket, udpSocket, relayEP);
            }
            catch
            {
                if (socket != null)
                    socket.Dispose();

                if (udpSocket != null)
                    udpSocket.Dispose();

                throw;
            }
        }

        #endregion
    }
}
