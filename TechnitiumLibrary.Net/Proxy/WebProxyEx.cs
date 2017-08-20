/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
        #region variables

        const int CONNECTION_TIMEOUT = 10000;
        const int SOCKET_SEND_TIMEOUT = 30000;
        const int SOCKET_RECV_TIMEOUT = 30000;

        #endregion

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
            Socket socket;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    if (Environment.OSVersion.Version.Major < 6)
                    {
                        //below vista
                        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    }
                    else
                    {
                        //vista & above
                        socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                        socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
                    }
                    break;

                case PlatformID.Unix: //mono framework
                    if (Socket.OSSupportsIPv6)
                        socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    else
                        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                    break;

                default: //unknown
                    socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    break;
            }

            IAsyncResult result = socket.BeginConnect(this.Address.Host, this.Address.Port, null, null);
            if (!result.AsyncWaitHandle.WaitOne(timeout))
                throw new SocketException((int)SocketError.TimedOut);

            if (!socket.Connected)
                throw new SocketException((int)SocketError.ConnectionRefused);

            socket.NoDelay = true;

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

        public Socket Connect(IPEndPoint remoteEP)
        {
            if (remoteEP.AddressFamily == AddressFamily.InterNetworkV6)
                return Connect("[" + remoteEP.Address.ToString() + "]", remoteEP.Port);
            else
                return Connect(remoteEP.Address.ToString(), remoteEP.Port);
        }

        public Socket Connect(IPAddress address, int port)
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return Connect("[" + address.ToString() + "]", port);
            else
                return Connect(address.ToString(), port);
        }

        public Socket Connect(string address, int port)
        {
            Socket socket = GetProxyConnection(CONNECTION_TIMEOUT);

            socket.SendTimeout = SOCKET_SEND_TIMEOUT;
            socket.ReceiveTimeout = SOCKET_RECV_TIMEOUT;

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

                socket.Send(Encoding.ASCII.GetBytes(httpConnectRequest));

                byte[] buffer = new byte[128];
                int bytesRecv = socket.Receive(buffer);

                if (bytesRecv < 1)
                    throw new WebException("No response was received from Http proxy server.");

                string[] httpResponse = Encoding.ASCII.GetString(buffer, 0, bytesRecv).Split('\r')[0].Split(new char[] { ' ' }, 3);

                switch (httpResponse[1])
                {
                    case "200":
                        return socket;

                    case "407":
                        throw new WebException("The remote server returned an error: (" + httpResponse[1] + ") Proxy Authorization Required");

                    default:
                        throw new WebException("The remote server returned an error: (" + httpResponse[1] + ") " + httpResponse[2]);
                }
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        #endregion
    }
}
