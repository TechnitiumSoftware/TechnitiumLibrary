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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksProxy : NetProxy
    {
        #region variables

        SocksProxyNegotiationRequest _negotiationRequest;
        SocksProxyAuthenticationRequest _authRequest;

        bool _isUdpAvailableChecked;
        bool _isUdpAvailable;

        #endregion

        #region constructor

        public SocksProxy(EndPoint proxyEP, NetworkCredential credential = null)
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
                _negotiationRequest = new SocksProxyNegotiationRequest(new SocksProxyAuthenticationMethod[] { SocksProxyAuthenticationMethod.NoAuthenticationRequired });
            }
            else
            {
                _negotiationRequest = new SocksProxyNegotiationRequest(new SocksProxyAuthenticationMethod[] { SocksProxyAuthenticationMethod.NoAuthenticationRequired, SocksProxyAuthenticationMethod.UsernamePassword });
                _authRequest = new SocksProxyAuthenticationRequest(_credential.UserName, _credential.Password);
            }
        }

        private async Task AuthenticateAsync(Stream s)
        {
            await _negotiationRequest.WriteToAsync(s);
            await s.FlushAsync();

            SocksProxyNegotiationReply negotiationReply = await SocksProxyNegotiationReply.ReadRequestAsync(s);
            if (!negotiationReply.IsVersionSupported)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            switch (negotiationReply.Method)
            {
                case SocksProxyAuthenticationMethod.UsernamePassword:
                    if (_authRequest == null)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server requires authentication.");

                    await _authRequest.WriteToAsync(s);
                    await s.FlushAsync();

                    SocksProxyAuthenticationReply authenticationReply = await SocksProxyAuthenticationReply.ReadRequestAsync(s);
                    if (!authenticationReply.IsVersionSupported)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server does not support username/password method version 1.");

                    if (authenticationReply.Status != SocksProxyAuthenticationStatus.Success)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server authentication failed: invalid username or password.");

                    break;

                case SocksProxyAuthenticationMethod.NoAuthenticationRequired:
                    break;

                case SocksProxyAuthenticationMethod.NoAcceptableMethods:
                    if (_authRequest == null)
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server requires authentication.");
                    else
                        throw new SocksProxyAuthenticationFailedException("Socks proxy server does not support username/password method.");

                default:
                    throw new SocksProxyException("Socks proxy server returned unknown method.");
            }
        }

        private static async Task<EndPoint> RequestAsync(Stream s, SocksProxyRequest request)
        {
            await request.WriteToAsync(s);
            await s.FlushAsync();

            SocksProxyReply reply = await SocksProxyReply.ReadReplyAsync(s);
            if (!reply.IsVersionSupported)
                throw new SocksProxyException("Socks version 5 is not supported by the proxy server.");

            if (reply.ReplyCode != SocksProxyReplyCode.Succeeded)
                throw new SocksProxyException("Socks proxy server request failed: " + reply.ReplyCode.ToString(), reply.ReplyCode);

            return reply.BindEndPoint;
        }

        #endregion

        #region protected

        protected override async Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket)
        {
            try
            {
                Stream stream = new WriteBufferedStream(new NetworkStream(viaSocket));

                await AuthenticateAsync(stream);
                await RequestAsync(stream, new SocksProxyRequest(SocksProxyRequestCommand.Connect, remoteEP));

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

        public override async Task<bool> IsUdpAvailableAsync()
        {
            if (_isUdpAvailableChecked)
                return _isUdpAvailable;

            SocksProxyUdpAssociateHandler udpHandler = null;

            try
            {
                udpHandler = await UdpAssociateAsync();

                _isUdpAvailable = true;
            }
            catch (SocksProxyException ex)
            {
                if (ex.ReplyCode == SocksProxyReplyCode.CommandNotSupported)
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

        public override async Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
        {
            try
            {
                return await BindAsync(family);
            }
            catch (NotSupportedException)
            {
                return new SocksProxyBindHandler(SocksProxyReplyCode.AddressTypeNotSupported);
            }
            catch (SocksProxyException ex)
            {
                return new SocksProxyBindHandler(ex.ReplyCode);
            }
            catch
            {
                return new SocksProxyBindHandler(SocksProxyReplyCode.GeneralSocksServerFailure);
            }
        }

        public override async Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
        {
            return await UdpAssociateAsync(localEP);
        }

        public override async Task<int> UdpQueryAsync(byte[] request, int requestOffset, int requestCount, byte[] response, int responseOffset, int responseCount, EndPoint remoteEP, int timeout = 10000, int retries = 1, bool expBackoffTimeout = false, CancellationToken cancellationToken = default)
        {
            if (IsBypassed(remoteEP))
            {
                IPEndPoint hostEP = await remoteEP.GetIPEndPointAsync();

                using (Socket socket = new Socket(hostEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    return await socket.UdpQueryAsync(request, requestOffset, requestCount, response, responseOffset, responseCount, remoteEP, timeout, retries, expBackoffTimeout, cancellationToken);
                }
            }

            if (_viaProxy != null)
                throw new NotSupportedException("Cannot chain proxies for Udp protocol.");

            using (SocksProxyUdpAssociateHandler proxyUdpRequestHandler = await UdpAssociateAsync())
            {
                return await proxyUdpRequestHandler.UdpQueryAsync(request, requestOffset, requestCount, response, responseOffset, responseCount, remoteEP, timeout, retries, expBackoffTimeout, cancellationToken);
            }
        }

        public async Task<SocksProxyBindHandler> BindAsync(AddressFamily family = AddressFamily.InterNetwork)
        {
            EndPoint endPoint;

            switch (family)
            {
                case AddressFamily.InterNetwork:
                    endPoint = new IPEndPoint(IPAddress.Any, 0);
                    break;

                case AddressFamily.InterNetworkV6:
                    endPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
                    break;

                default:
                    throw new NotSupportedException("Address family not supported.");
            }

            //connect to proxy server
            Socket socket = await GetTcpConnectionAsync(_proxyEP);

            try
            {
                Stream stream = new WriteBufferedStream(new NetworkStream(socket));

                await AuthenticateAsync(stream);
                EndPoint bindEP = await RequestAsync(stream, new SocksProxyRequest(SocksProxyRequestCommand.Bind, endPoint));

                return new SocksProxyBindHandler(socket, bindEP);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public Task<SocksProxyUdpAssociateHandler> UdpAssociateAsync()
        {
            return UdpAssociateAsync(new IPEndPoint(IPAddress.Any, 0));
        }

        public Task<SocksProxyUdpAssociateHandler> UdpAssociateAsync(int localPort)
        {
            return UdpAssociateAsync(new IPEndPoint(IPAddress.Any, localPort));
        }

        public async Task<SocksProxyUdpAssociateHandler> UdpAssociateAsync(EndPoint localEP)
        {
            //bind local ep
            Socket udpSocket = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(localEP);

            //connect to proxy server
            Socket socket = await GetTcpConnectionAsync(_proxyEP);

            try
            {
                Stream stream = new WriteBufferedStream(new NetworkStream(socket));

                await AuthenticateAsync(stream);
                EndPoint relayEP = await RequestAsync(stream, new SocksProxyRequest(SocksProxyRequestCommand.UdpAssociate, udpSocket.LocalEndPoint));

                return new SocksProxyUdpAssociateHandler(socket, udpSocket, relayEP);
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
