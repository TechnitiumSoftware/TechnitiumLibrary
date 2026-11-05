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

        readonly string _hostname;
        readonly int _port;
        readonly string _username;
        readonly string _password;
        readonly bool _ssl = false;
        readonly bool _ignoreCertificateErrors = false;
        readonly bool _preferSecureAuth = true;

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
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                try
                {
                    if ((_sW != null) && (_sock != null) && _sock.Connected)
                    {
                        _sW.WriteLine("QUIT");
                        _sR?.ReadLine();
                    }
                }
                catch
                { }

                if (_sW != null)
                    _sW.Dispose();

                if (_sR != null)
                    _sR.Dispose();

                if (_sock != null)
                    _sock.Dispose();

                _sock = null;
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

            if (HasPop3LineBreak(_username) || HasPop3LineBreak(_password))
                throw new Pop3Exception("Username or password contains a CR or LF character.");

            TcpClient sock = new TcpClient(_hostname, _port);
            StreamReader reader = null;
            StreamWriter writer = null;

            try
            {
                Stream stream;

                if (_ssl)
                {
                    SslStream sslStream;

                    if (_ignoreCertificateErrors)
                        sslStream = new SslStream(sock.GetStream(), false, RemoteCertificateValidationCallback);
                    else
                        sslStream = new SslStream(sock.GetStream(), false);

                    sslStream.AuthenticateAsClient(_hostname);

                    stream = sslStream;
                }
                else
                    stream = sock.GetStream();

                reader = new StreamReader(stream, Encoding.Latin1, false, 1);
                writer = new StreamWriter(stream, Encoding.ASCII, 1);
                writer.AutoFlush = true;

                string response = reader.ReadLine();
                if (response == null)
                    throw new Pop3Exception("No response from server.");
                if (IsPop3Error(response))
                    throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));

                int i = response.IndexOf('<');
                int j = response.LastIndexOf('>');
                bool secureAuthAvailable = ((i > -1) && (j > i));

                if (_preferSecureAuth && secureAuthAvailable)
                {
                    string timestamp = response.Substring(i, j - i + 1);
                    string digest = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(timestamp + _password))).ToLowerInvariant();

                    writer.WriteLine("APOP " + _username + " " + digest);
                    response = reader.ReadLine();
                    if (response == null)
                        throw new Pop3Exception("No response from server.");
                    if (IsPop3Error(response))
                        throw new Pop3InvalidUsernamePasswordException("Server returned: " + Pop3ErrorText(response));
                }
                else
                {
                    writer.WriteLine("USER " + _username);
                    response = reader.ReadLine();
                    if (response == null)
                        throw new Pop3Exception("No response from server.");
                    if (IsPop3Error(response))
                        throw new Pop3InvalidUsernamePasswordException("Server returned: " + Pop3ErrorText(response));

                    writer.WriteLine("PASS " + _password);
                    response = reader.ReadLine();
                    if (response == null)
                        throw new Pop3Exception("No response from server.");
                    if (IsPop3Error(response))
                        throw new Pop3InvalidUsernamePasswordException("Server returned: " + Pop3ErrorText(response));
                }

                _sock = sock;
                _sR = reader;
                _sW = writer;
            }
            catch
            {
                try
                {
                    writer?.Dispose();
                }
                catch
                { }

                try
                {
                    reader?.Dispose();
                }
                catch
                { }

                sock.Dispose();
                throw;
            }
        }

        public void Close()
        {
            if (_sock != null)
            {
                try
                {
                    if ((_sW != null) && _sock.Connected)
                    {
                        _sW.WriteLine("QUIT");
                        _sR?.ReadLine();
                    }
                }
                catch
                { }

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
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));
        }

        public Pop3Stats STAT()
        {
            _sW.WriteLine("STAT");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));

            string[] tmp = response.Substring(4).Split(new char[] { ' ' });

            return new Pop3Stats() { TotalMessages = Convert.ToInt32(tmp[0]), TotalSize = Convert.ToInt32(tmp[1]) };
        }

        public Pop3MessageInfo[] LIST()
        {
            _sW.WriteLine("LIST");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));

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
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    string tmp = _sR.ReadLine();
                    if (tmp == null)
                        throw new EndOfStreamException();
                    if (tmp == ".")
                        break;

                    if (tmp.StartsWith('.'))
                        tmp = tmp.Substring(1);

                    byte[] tmp2 = Encoding.Latin1.GetBytes(tmp);
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
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));

            using (MemoryStream mS = new MemoryStream())
            {
                while (true)
                {
                    string tmp = _sR.ReadLine();
                    if (tmp == null)
                        throw new EndOfStreamException();
                    if (tmp == ".")
                        break;

                    if (tmp.StartsWith('.'))
                        tmp = tmp.Substring(1);

                    byte[] tmp2 = Encoding.Latin1.GetBytes(tmp);
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
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));
        }

        public void NOOP()
        {
            _sW.WriteLine("NOOP");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));
        }

        public void RSET()
        {
            _sW.WriteLine("RSET");
            string response = _sR.ReadLine();
            if (response == null)
                throw new Pop3Exception("No response from server.");
            if (IsPop3Error(response))
                throw new Pop3Exception("Server returned: " + Pop3ErrorText(response));
        }

        static bool HasPop3LineBreak(string value)
        {
            return (value != null) && (value.IndexOfAny(new char[] { '\r', '\n' }) >= 0);
        }

        static bool IsPop3Error(string response)
        {
            return response.StartsWith("-ERR", StringComparison.Ordinal) && ((response.Length == 4) || (response[4] == ' '));
        }

        static string Pop3ErrorText(string response)
        {
            if ((response.Length > 5) && (response[4] == ' '))
                return response.Substring(5);

            return "";
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
