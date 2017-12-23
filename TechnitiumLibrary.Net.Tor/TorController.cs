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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace TechnitiumLibrary.Net.Tor
{
    public enum TorProxyType
    {
        None = 0,
        Http = 1,
        Https = 2,
        Socks4 = 3,
        Socks5 = 4
    }

    public class TorController : IDisposable
    {
        #region variables

        readonly string _torExecutableFile;
        int _controlPort = 9051;
        IPEndPoint _Socks5EP;

        TorProxyType _proxyType;
        string _proxyHost;
        int _proxyPort;
        NetworkCredential _proxyCredential;

        Process _process;
        Socket _socket;

        StreamWriter _sW;
        StreamReader _sR;

        #endregion

        #region constructor

        public TorController(string torExecutableFile)
        {
            _torExecutableFile = torExecutableFile;
        }

        #endregion

        #region IDisposable Support

        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_process != null)
                        Stop();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private string HashPassword(string password)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo(_torExecutableFile, "--hash-password " + password);

            processInfo.UseShellExecute = false;
            processInfo.RedirectStandardOutput = true;
            processInfo.CreateNoWindow = true;

            using (Process process = Process.Start(processInfo))
            {
                StreamReader sR = process.StandardOutput;

                while (true)
                {
                    string response = sR.ReadLine();
                    if (response == null)
                        break;

                    if (response.StartsWith("16:"))
                        return response;
                }
            }

            throw new TorControllerException("Unable to hash password.");
        }

        #endregion

        #region public

        public void Start(int connectionTimeout = 10000)
        {
            if (_process == null)
            {
                string password;

                {
                    RandomNumberGenerator rnd = new RNGCryptoServiceProvider();
                    byte[] buffer = new byte[32];
                    rnd.GetBytes(buffer);

                    password = BitConverter.ToString(buffer).Replace("-", "").ToLower();
                }

                string arguments = "--controlport " + _controlPort + " --HashedControlPassword " + HashPassword(password);

                if (_Socks5EP != null)
                    arguments += " --SocksPort " + _Socks5EP.ToString();

                switch (_proxyType)
                {
                    case TorProxyType.Http:
                        arguments += " --HTTPProxy " + _proxyHost + (_proxyPort == 0 ? "" : ":" + _proxyPort);

                        if (_proxyCredential != null)
                            arguments += " --HTTPProxyAuthenticator " + _proxyCredential.UserName + ":" + _proxyCredential.Password;

                        break;

                    case TorProxyType.Https:
                        arguments += " --HTTPSProxy " + _proxyHost + (_proxyPort == 0 ? "" : ":" + _proxyPort);

                        if (_proxyCredential != null)
                            arguments += " --HTTPSProxyAuthenticator " + _proxyCredential.UserName + ":" + _proxyCredential.Password;

                        break;

                    case TorProxyType.Socks4:
                        arguments += " --Socks4Proxy " + _proxyHost + (_proxyPort == 0 ? "" : ":" + _proxyPort);
                        break;

                    case TorProxyType.Socks5:
                        arguments += " --Socks5Proxy " + _proxyHost + (_proxyPort == 0 ? "" : ":" + _proxyPort);

                        if (_proxyCredential != null)
                        {
                            arguments += " --Socks5ProxyUsername " + _proxyCredential.UserName;
                            arguments += " --Socks5ProxyPassword " + _proxyCredential.Password;
                        }

                        break;
                }

                ProcessStartInfo processInfo = new ProcessStartInfo(_torExecutableFile, arguments);

                processInfo.UseShellExecute = false;
                processInfo.CreateNoWindow = true;

                _process = Process.Start(processInfo);
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                IAsyncResult result = _socket.BeginConnect(IPAddress.Loopback, _controlPort, null, null);

                if (!result.AsyncWaitHandle.WaitOne(connectionTimeout))
                    throw new SocketException((int)SocketError.TimedOut);

                if (!_socket.Connected)
                    throw new SocketException((int)SocketError.ConnectionRefused);

                NetworkStream stream = new NetworkStream(_socket);

                _sR = new StreamReader(stream);
                _sW = new StreamWriter(stream);
                _sW.AutoFlush = true;

                _sW.WriteLine("AUTHENTICATE \"" + password + "\"");
                string response = _sR.ReadLine();
                if (!response.StartsWith("250 "))
                    throw new TorControllerException("Authentication failed: " + response);

                _sW.WriteLine("SETCONF __OwningControllerProcess=" + Process.GetCurrentProcess().Id);
                response = _sR.ReadLine();
                if (!response.StartsWith("250 "))
                    throw new TorControllerException("Server returned: " + response);

                _sW.WriteLine("TAKEOWNERSHIP");
                response = _sR.ReadLine();
                if (!response.StartsWith("250 "))
                    throw new TorControllerException("Server returned: " + response);
            }
        }

        public void Stop()
        {
            if (_process != null)
            {
                Shutdown();

                _socket.Close();

                try
                {
                    if (!_process.WaitForExit(10000))
                        _process.Kill();
                }
                catch
                { }

                _process = null;
            }
        }

        public void Shutdown()
        {
            _sW.WriteLine("SIGNAL SHUTDOWN");
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        public void SwitchCircuits()
        {
            _sW.WriteLine("SIGNAL NEWNYM");
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        public void ClearDnsCache()
        {
            _sW.WriteLine("SIGNAL CLEARDNSCACHE");
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        public void ImmediateShutdown()
        {
            _sW.WriteLine("SIGNAL HALT");
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        public TorHiddenServiceInfo CreateHiddenService(int virtualPort, IPEndPoint localHiddenEP = null, string clientBasicAuthUser = null, string clientBasicAuthCookie = null)
        {
            _sW.WriteLine("ADD_ONION NEW:BEST" + (clientBasicAuthUser == null ? "" : " Flags=BasicAuth") + " Port=" + virtualPort + (localHiddenEP == null ? "" : "," + localHiddenEP.ToString()) + (clientBasicAuthUser == null ? "" : " ClientAuth=" + clientBasicAuthUser + (clientBasicAuthCookie == null ? "" : ":" + clientBasicAuthCookie)));
            return new TorHiddenServiceInfo(_sR);
        }

        public TorHiddenServiceInfo CreateHiddenService(int virtualPort, string rsaPrivateKey, IPEndPoint localHiddenEP = null, string clientBasicAuthUser = null, string clientBasicAuthCookie = null)
        {
            _sW.WriteLine("ADD_ONION " + rsaPrivateKey + (clientBasicAuthUser == null ? "" : " Flags=BasicAuth") + " Port=" + virtualPort + (localHiddenEP == null ? "" : "," + localHiddenEP.ToString()) + (clientBasicAuthUser == null ? "" : " ClientAuth=" + clientBasicAuthUser + ":" + (clientBasicAuthCookie == null ? "" : ":" + clientBasicAuthCookie)));
            return new TorHiddenServiceInfo(_sR);
        }

        public void DeleteHiddenService(string serviceId)
        {
            _sW.WriteLine("DEL_ONION " + serviceId);
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        #endregion

        #region properties

        public string TorExecutableFile
        { get { return _torExecutableFile; } }

        public int ControlPort
        {
            get { return _controlPort; }
            set { _controlPort = value; }
        }

        public IPEndPoint Socks5EndPoint
        {
            get { return _Socks5EP; }
            set { _Socks5EP = value; }
        }

        public TorProxyType ProxyType
        {
            get { return _proxyType; }
            set { _proxyType = value; }
        }

        public string ProxyHost
        {
            get { return _proxyHost; }
            set { _proxyHost = value; }
        }

        public int ProxyPort
        {
            get { return _proxyPort; }
            set { _proxyPort = value; }
        }

        public NetworkCredential ProxtCredential
        {
            get { return _proxyCredential; }
            set { _proxyCredential = value; }
        }

        #endregion
    }
}
