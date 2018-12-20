/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
    public class WebProxyEx : WebProxy
    {
        #region constructors

        public WebProxyEx()
            : base()
        { }

        public WebProxyEx(string Address)
            : base(Address)
        { }

        public WebProxyEx(Uri Address)
            : base(Address)
        { }

        public WebProxyEx(string Address, bool BypassOnLocal)
            : base(Address, BypassOnLocal)
        { }

        public WebProxyEx(string Host, int Port)
            : base(Host, Port)
        { }

        public WebProxyEx(Uri Address, bool BypassOnLocal)
            : base(Address, BypassOnLocal)
        { }

        public WebProxyEx(string Address, bool BypassOnLocal, string[] BypassList)
            : base(Address, BypassOnLocal, BypassList)
        { }

        public WebProxyEx(Uri Address, bool BypassOnLocal, string[] BypassList)
            : base(Address, BypassOnLocal, BypassList)
        { }

        public WebProxyEx(string Address, bool BypassOnLocal, string[] BypassList, ICredentials Credentials)
            : base(Address, BypassOnLocal, BypassList, Credentials)
        { }

        public WebProxyEx(Uri Address, bool BypassOnLocal, string[] BypassList, ICredentials Credentials)
            : base(Address, BypassOnLocal, BypassList, Credentials)
        { }

        #endregion

        #region private

        private Socket GetProxyConnection(int timeout)
        {
            IPAddress[] ipAddresses = System.Net.Dns.GetHostAddresses(this.Address.Host);
            if (ipAddresses.Length == 0)
                throw new SocketException((int)SocketError.HostNotFound);

            IPEndPoint hostEP = new IPEndPoint(ipAddresses[0], this.Address.Port);
            Socket socket;

            switch (hostEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    break;

                case AddressFamily.InterNetworkV6:
                    socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            IAsyncResult result = socket.BeginConnect(hostEP, null, null);
            if (!result.AsyncWaitHandle.WaitOne(timeout))
                throw new SocketException((int)SocketError.TimedOut);

            if (!socket.Connected)
                throw new SocketException((int)SocketError.ConnectionRefused);

            return socket;
        }

        #endregion

        #region public

        public bool IsProxyAvailable()
        {
            try
            {
                using (Socket socket = GetProxyConnection(5000))
                { }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public void CheckProxyAccess()
        {
            using (Socket socket = GetProxyConnection(5000))
            { }
        }

        public Socket Connect(EndPoint remoteEP, int timeout = 10000)
        {
            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        IPEndPoint ep = remoteEP as IPEndPoint;
                        return Connect(ep.Address.ToString(), ep.Port, timeout);
                    }

                case AddressFamily.InterNetworkV6:
                    {
                        IPEndPoint ep = remoteEP as IPEndPoint;
                        return Connect("[" + ep.Address.ToString() + "]", ep.Port, timeout);
                    }

                case AddressFamily.Unspecified: //domain
                    {
                        DomainEndPoint ep = remoteEP as DomainEndPoint;
                        return Connect(ep.Address, ep.Port, timeout);
                    }

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

        public Socket Connect(IPAddress address, int port, int timeout = 10000)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return Connect(address.ToString(), port, timeout);

                case AddressFamily.InterNetworkV6:
                    return Connect("[" + address.ToString() + "]", port, timeout);

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

        public Socket Connect(string address, int port, int timeout = 10000)
        {
            Socket socket = GetProxyConnection(timeout);

            socket.SendTimeout = timeout;
            socket.ReceiveTimeout = timeout;

            return Connect(address, port, socket);
        }

        public Socket Connect(EndPoint remoteEP, Socket viaSocket)
        {
            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        IPEndPoint ep = remoteEP as IPEndPoint;
                        return Connect(ep.Address.ToString(), ep.Port, viaSocket);
                    }

                case AddressFamily.InterNetworkV6:
                    {
                        IPEndPoint ep = remoteEP as IPEndPoint;
                        return Connect("[" + ep.Address.ToString() + "]", ep.Port, viaSocket);
                    }

                case AddressFamily.Unspecified: //domain
                    {
                        DomainEndPoint ep = remoteEP as DomainEndPoint;
                        return Connect(ep.Address, ep.Port, viaSocket);
                    }

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

        public Socket Connect(string address, int port, Socket viaSocket)
        {
            try
            {
                NetworkCredential credentials = null;

                if (this.UseDefaultCredentials)
                    credentials = CredentialCache.DefaultCredentials.GetCredential(this.Address, "BASIC");
                else if (this.Credentials != null)
                    credentials = this.Credentials.GetCredential(this.Address, "BASIC");

                string httpConnectRequest = "CONNECT " + address + ":" + port + " HTTP/1.0\r\n";

                if (credentials != null)
                    httpConnectRequest += "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials.UserName + ":" + credentials.Password)) + "\r\n";

                httpConnectRequest += "\r\n";

                viaSocket.Send(Encoding.ASCII.GetBytes(httpConnectRequest));

                byte[] buffer = new byte[128];
                int bytesRecv = viaSocket.Receive(buffer);

                if (bytesRecv < 1)
                    throw new WebProxyExException("No response was received from Http proxy server.");

                string httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRecv);
                string[] httpResponseParts = httpResponse.Split('\r')[0].Split(new char[] { ' ' }, 3);

                if (httpResponseParts.Length != 3)
                    throw new WebProxyExException("Invalid response received from remote server: " + httpResponse);

                switch (httpResponseParts[1])
                {
                    case "200":
                        return viaSocket;

                    case "407":
                        throw new WebProxyExAuthenticationFailedException("The remote server returned an error: (" + httpResponseParts[1] + ") Proxy Authorization Required");

                    default:
                        throw new WebProxyExException("The remote server returned an error: (" + httpResponseParts[1] + ") " + httpResponseParts[2]);
                }
            }
            catch
            {
                viaSocket.Dispose();
                throw;
            }
        }

        #endregion

        #region properties

        public EndPoint ProxyEndPoint
        {
            get
            {
                if (IPAddress.TryParse(this.Address.Host, out IPAddress address))
                    return new IPEndPoint(address, this.Address.Port);
                else
                    return new DomainEndPoint(this.Address.Host, this.Address.Port);
            }
        }

        #endregion
    }

    public class WebProxyExException : NetProxyException
    {
        #region constructors

        public WebProxyExException()
            : base()
        { }

        public WebProxyExException(string message)
            : base(message)
        { }

        public WebProxyExException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected WebProxyExException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }

    public class WebProxyExAuthenticationFailedException : NetProxyAuthenticationFailedException
    {
        #region constructors

        public WebProxyExAuthenticationFailedException()
            : base()
        { }

        public WebProxyExAuthenticationFailedException(string message)
            : base(message)
        { }

        public WebProxyExAuthenticationFailedException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected WebProxyExAuthenticationFailedException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}
