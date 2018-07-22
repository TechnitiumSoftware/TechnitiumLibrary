/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TechnitiumLibrary.Net.Mail
{
    public class Pop3Client : IDisposable
    {
        #region variables

        TcpClient _sock;

        string _hostname;
        int _port;
        string _username;
        string _password;
        bool _ssl = false;
        bool _ignoreCertificateErrors = false;
        bool _preferSecureAuth = true;

        StreamWriter _sW;
        StreamReader _sR;

        #endregion

        #region constructors

        public Pop3Client(string hostname, int port, string username, string password, bool ssl = false, bool ignoreCertificateErrors = false, bool preferSecureAuth = true)
        {
            _hostname = hostname;
            _port = port;
            _username = username;
            _password = password;
            _ssl = ssl;
            _ignoreCertificateErrors = ignoreCertificateErrors;
            _preferSecureAuth = preferSecureAuth;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_sW != null)
                    _sW.Dispose();

                if (_sR != null)
                    _sR.Dispose();

                if (_sock != null)
                    _sock.Dispose();
            }

            _disposed = true;
        }

        #endregion

        #region private

        private bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; //ignore cert errors
        }

        #endregion

        #region public

        public void Connect()
        {
            if (_sock != null)
                throw new Pop3Exception("Pop3Client previous connection was not closed.");

            _sock = new TcpClient(_hostname, _port);

            Stream stream;

            if (_ssl)
            {
                SslStream sslStream;

                if (_ignoreCertificateErrors)
                    sslStream = new SslStream(_sock.GetStream(), false, RemoteCertificateValidationCallback);
                else
                    sslStream = new SslStream(_sock.GetStream(), false);

                sslStream.AuthenticateAsClient(_hostname);

                stream = sslStream;
            }
            else
                stream = _sock.GetStream();

            _sR = new StreamReader(stream, Encoding.ASCII, false, 1);
            _sW = new StreamWriter(stream, Encoding.ASCII, 1);
            _sW.AutoFlush = true;

            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));

            int i = response.IndexOf('<');
            int j = response.LastIndexOf('>');
            bool secureAuthAvailable = ((i > -1) && (j > i));

            if (_preferSecureAuth && secureAuthAvailable)
            {
                string timestamp = response.Substring(i, j - i + 1);
                string digest = BitConverter.ToString(HashAlgorithm.Create("MD5").ComputeHash(Encoding.ASCII.GetBytes(timestamp + _password))).Replace("-", "").ToLower();

                _sW.WriteLine("APOP " + _username + " " + digest);
                response = _sR.ReadLine();
                if (response == null)
                    throw new Pop3Exception("No response from server.");
                if (response.StartsWith("-ERR "))
                    throw new Pop3InvalidUsernamePasswordException("Server returned: " + response.Substring(5));
            }
            else
            {
                _sW.WriteLine("USER " + _username);
                response = _sR.ReadLine();
                if (response == null)
                    throw new Pop3Exception("No response from server.");
                if (response.StartsWith("-ERR "))
                    throw new Pop3InvalidUsernamePasswordException("Server returned: " + response.Substring(5));

                _sW.WriteLine("PASS " + _password);
                response = _sR.ReadLine();
                if (response == null)
                    throw new Pop3Exception("No response from server.");
                if (response.StartsWith("-ERR "))
                    throw new Pop3InvalidUsernamePasswordException("Server returned: " + response.Substring(5));
            }
        }

        public void Close()
        {
            if (_sock != null)
            {
                _sock.Close();
                _sock = null;
            }
        }

        public void QUIT()
        {
            _sW.WriteLine("QUIT");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));
        }

        public Pop3Stats STAT()
        {
            _sW.WriteLine("STAT");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));

            string[] tmp = response.Substring(4).Split(new char[] { ' ' });

            return new Pop3Stats() { TotalMessages = Convert.ToInt32(tmp[0]), TotalSize = Convert.ToInt32(tmp[1]) };
        }

        public Pop3MessageInfo[] LIST()
        {
            _sW.WriteLine("LIST");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));

            List<Pop3MessageInfo> info = new List<Pop3MessageInfo>();

            while (true)
            {
                string tmp = _sR.ReadLine();
                if (tmp == ".")
                    break;

                string[] tmp2 = tmp.Split(new char[] { ' ' });

                info.Add(new Pop3MessageInfo() { MessageNumber = Convert.ToInt32(tmp2[0]), MessageSize = Convert.ToInt32(tmp2[1]) });
            }

            return info.ToArray();
        }

        public byte[] RETR(int messageNumber)
        {
            _sW.WriteLine("RETR " + messageNumber);
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    string tmp = _sR.ReadLine();
                    if (tmp == ".")
                        break;

                    byte[] tmp2 = Encoding.ASCII.GetBytes(tmp);
                    mS.Write(tmp2, 0, tmp2.Length);
                    mS.WriteByte(0x0d);
                    mS.WriteByte(0x0a);
                }

                return mS.ToArray();
            }
        }

        public byte[] TOP(int messageNumber, int lines)
        {
            _sW.WriteLine("TOP " + messageNumber + " " + lines);
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    string tmp = _sR.ReadLine();
                    if (tmp == ".")
                        break;

                    byte[] tmp2 = Encoding.ASCII.GetBytes(tmp);
                    mS.Write(tmp2, 0, tmp2.Length);
                    mS.WriteByte(0x0d);
                    mS.WriteByte(0x0a);
                }

                return mS.ToArray();
            }
        }

        public void DELE(int messageNumber)
        {
            _sW.WriteLine("DELE " + messageNumber);
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));
        }

        public void NOOP()
        {
            _sW.WriteLine("NOOP");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));
        }

        public void RSET()
        {
            _sW.WriteLine("RSET");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (response.StartsWith("-ERR "))
                throw new Pop3Exception("Server returned: " + response.Substring(5));
        }

        #endregion
    }

    public class Pop3Stats
    {
        public int TotalMessages;
        public int TotalSize;
    }

    public class Pop3MessageInfo
    {
        public int MessageNumber;
        public int MessageSize;
    }

    [System.Serializable()]
    public class Pop3Exception : Exception
    {
        public Pop3Exception()
            : base()
        { }

        public Pop3Exception(string message)
            : base(message)
        { }

        public Pop3Exception(string message, Exception innerException)
            : base(message, innerException)
        { }
    }

    [System.Serializable()]
    public class Pop3InvalidUsernamePasswordException : Pop3Exception
    {
        public Pop3InvalidUsernamePasswordException()
            : base()
        { }

        public Pop3InvalidUsernamePasswordException(string message)
            : base(message)
        { }

        public Pop3InvalidUsernamePasswordException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }
}
