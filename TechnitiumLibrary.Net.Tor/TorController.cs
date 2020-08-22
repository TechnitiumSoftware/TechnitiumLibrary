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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;

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

        static readonly RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        readonly object _lock = new object();

        readonly string _torExecutableFilePath;
        int _controlPort = 9051;
        IPEndPoint _Socks5EP;

        TorProxyType _proxyType = TorProxyType.None;
        string _proxyHost;
        int _proxyPort;
        NetworkCredential _proxyCredential;

        Process _process;
        Socket _socket;

        StreamWriter _sW;
        StreamReader _sR;

        #endregion

        #region constructor

        public TorController(string torExecutableFilePath)
        {
            if (!File.Exists(torExecutableFilePath))
                throw new ArgumentException("Tor executable file was not found: " + torExecutableFilePath);

            _torExecutableFilePath = torExecutableFilePath;
        }

        #endregion

        #region IDisposable

        bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
                Stop();

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private string HashPassword(string password)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo(_torExecutableFilePath, "--hash-password " + password);

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
            lock (_lock)
            {
                if (IsRunning)
                    return;

                string password;

                {
                    byte[] buffer = new byte[32];
                    _rnd.GetBytes(buffer);

                    password = BitConverter.ToString(buffer).Replace("-", "").ToLower();
                }

                string dataDir = Path.Combine(Path.GetDirectoryName(_torExecutableFilePath), "data");
                if (!Directory.Exists(dataDir))
                    Directory.CreateDirectory(dataDir);

                string arguments = "--DataDirectory \"" + dataDir + "\" --controlport " + _controlPort + " --HashedControlPassword " + HashPassword(password);

                if (_Socks5EP == null)
                    _Socks5EP = new IPEndPoint(IPAddress.Loopback, 9050); //default
                else
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

                ProcessStartInfo processInfo = new ProcessStartInfo(_torExecutableFilePath, arguments);

                processInfo.UseShellExecute = false;
                processInfo.CreateNoWindow = true;

                Process process = Process.Start(processInfo);

                int retry = 1;
                while (true)
                {
                    try
                    {
                        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        _socket.ReceiveTimeout = 5000;
                        _socket.SendTimeout = 5000;
                        _socket.Connect(IPAddress.Loopback, _controlPort, connectionTimeout);

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

                        _process = process;
                        break;
                    }
                    catch
                    {
                        if (_socket != null)
                            _socket.Dispose();

                        if (retry < 3)
                        {
                            retry++;
                            Thread.Sleep(2000); //wait before retrying
                        }
                        else
                        {
                            try
                            {
                                process.Kill();
                            }
                            catch
                            { }

                            throw;
                        }
                    }
                }
            }
        }

        public void Stop(int waitTimeout = 10000)
        {
            lock (_lock)
            {
                if (IsRunning)
                {
                    try
                    {
                        Shutdown();

                        if (_socket.Connected)
                            _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch
                    { }

                    _socket.Dispose();

                    try
                    {
                        if (!_process.WaitForExit(waitTimeout))
                            _process.Kill();
                    }
                    catch
                    { }

                    _sW.Dispose();
                    _sR.Dispose();
                    _process.Dispose();
                    _process = null;
                }
            }
        }

        public void Shutdown()
        {
            _sW.WriteLine("SIGNAL SHUTDOWN");
            string response = _sR.ReadLine();
            if (!response.StartsWith("250 "))
                throw new TorControllerException("Server returned: " + response);
        }

        public void SwitchCircuit()
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

        public TorHiddenServiceInfo CreateHiddenService(int virtualPort, string privateKey, IPEndPoint localHiddenEP = null, string clientBasicAuthUser = null, string clientBasicAuthCookie = null)
        {
            _sW.WriteLine("ADD_ONION " + privateKey + (clientBasicAuthUser == null ? "" : " Flags=BasicAuth") + " Port=" + virtualPort + (localHiddenEP == null ? "" : "," + localHiddenEP.ToString()) + (clientBasicAuthUser == null ? "" : " ClientAuth=" + clientBasicAuthUser + ":" + (clientBasicAuthCookie == null ? "" : ":" + clientBasicAuthCookie)));
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
        { get { return _torExecutableFilePath; } }

        public bool IsRunning
        { get { return (_process != null) && !_process.HasExited; } }

        public int ControlPort
        {
            get { return _controlPort; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _controlPort = value;
            }
        }

        public IPEndPoint Socks5EndPoint
        {
            get { return _Socks5EP; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _Socks5EP = value;
            }
        }

        public TorProxyType ProxyType
        {
            get { return _proxyType; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _proxyType = value;
            }
        }

        public string ProxyHost
        {
            get { return _proxyHost; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _proxyHost = value;
            }
        }

        public int ProxyPort
        {
            get { return _proxyPort; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _proxyPort = value;
            }
        }

        public NetworkCredential ProxyCredential
        {
            get { return _proxyCredential; }
            set
            {
                if (_process != null)
                    throw new InvalidOperationException("Tor is already running.");

                _proxyCredential = value;
            }
        }

        #endregion
    }
}
