/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Mail
{
    public class SmtpClientEx : SmtpClient
    {
        #region variables

        readonly static RandomNumberGenerator _rng = new RNGCryptoServiceProvider();
        readonly static RemoteCertificateValidationCallback _existingServerCertificateValidationCallback;

        readonly static FieldInfo _localHostName = typeof(SmtpClient).GetField("_clientDomain", BindingFlags.Instance | BindingFlags.NonPublic);
        IDnsClient _dnsClient;
        NetProxy _proxy;
        bool _smtpOverTls;
        string _host;
        int _port;
        bool _ignoreCertificateErrors;

        TunnelProxy _tunnelProxy;

        #endregion

        #region constructors

        static SmtpClientEx()
        {
            _existingServerCertificateValidationCallback = ServicePointManager.ServerCertificateValidationCallback;
            ServicePointManager.ServerCertificateValidationCallback = ServerCertificateValidationCallback;
        }

        public SmtpClientEx()
            : base()
        { }

        public SmtpClientEx(string host)
            : base()
        {
            _host = host;
            _port = 25;
        }

        public SmtpClientEx(string host, int port)
            : base()
        {
            _host = host;
            _port = port;
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_tunnelProxy != null)
                    _tunnelProxy.Dispose();
            }

            _disposed = true;

            base.Dispose(disposing);
        }

        #endregion

        #region static

        private static bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            SmtpClientEx smtpClient = sender as SmtpClientEx;
            if (smtpClient != null)
            {
                if (smtpClient._ignoreCertificateErrors)
                    return true;

                switch (sslPolicyErrors)
                {
                    case SslPolicyErrors.None:
                        return true;

                    case SslPolicyErrors.RemoteCertificateNameMismatch:
                        if (smtpClient._proxy == null)
                            return false;

                        X509Certificate2 cert = certificate as X509Certificate2;
                        if (cert == null)
                            cert = new X509Certificate2(certificate);

                        return cert.GetNameInfo(X509NameType.DnsFromAlternativeName, false).Equals(smtpClient._host, StringComparison.OrdinalIgnoreCase);

                    default:
                        return false;
                }
            }
            else if (_existingServerCertificateValidationCallback != null)
            {
                return _existingServerCertificateValidationCallback(sender, certificate, chain, sslPolicyErrors);
            }
            else
            {
                return sslPolicyErrors == SslPolicyErrors.None;
            }
        }

        #endregion

        #region public

        public void SetRandomLocalHostName()
        {
            byte[] buffer = new byte[4];
            _rng.GetBytes(buffer);

            LocalHostName = BitConverter.ToString(buffer).Replace("-", "");
        }

        public new void Send(string from, string recipients, string subject, string body)
        {
            Send(new MailMessage(from, recipients, subject, body));
        }

        public new void Send(MailMessage message)
        {
            SendMailAsync(message).Sync();
        }

        public new void SendAsync(string from, string recipients, string subject, string body, object userToken)
        {
            throw new NotSupportedException();
        }

        public new void SendAsync(MailMessage message, object userToken)
        {
            throw new NotSupportedException();
        }

        public new async Task SendMailAsync(MailMessage message)
        {
            if (_disposed)
                throw new ObjectDisposedException("SmtpClientEx");

            if (message.To.Count == 0)
                throw new ArgumentException("Message does not contain receipent email address.");

            if (DeliveryMethod == SmtpDeliveryMethod.Network)
            {
                string host = _host;

                if (string.IsNullOrEmpty(host))
                {
                    //resolve MX for the receipent domain using IDnsClient
                    if (_dnsClient == null)
                        _dnsClient = new DnsClient() { Proxy = _proxy };

                    IReadOnlyList<string> mxAddresses = await Dns.DnsClient.ResolveMXAsync(_dnsClient, message.To[0].Host, true);
                    if (mxAddresses.Count > 0)
                    {
                        host = mxAddresses[0];
                    }
                    else
                    {
                        IReadOnlyList<IPAddress> addresses = await Dns.DnsClient.ResolveIPAsync(_dnsClient, message.To[0].Host);
                        if (addresses.Count == 0)
                            throw new SocketException((int)SocketError.HostNotFound);

                        host = addresses[0].ToString();
                    }

                    _port = 25;
                    Credentials = null;
                }

                if (_proxy == null)
                {
                    if (!IPAddress.TryParse(host, out IPAddress hostIP))
                    {
                        //resolve host using IDnsClient
                        if (_dnsClient == null)
                            _dnsClient = new DnsClient() { Proxy = _proxy };

                        IReadOnlyList<IPAddress> addresses = await Dns.DnsClient.ResolveIPAsync(_dnsClient, host);
                        if (addresses.Count == 0)
                            throw new SocketException((int)SocketError.HostNotFound);

                        hostIP = addresses[0];
                    }

                    if (_smtpOverTls)
                    {
                        IPEndPoint remoteEP = new IPEndPoint(hostIP, _port);

                        if ((_tunnelProxy != null) && !_tunnelProxy.RemoteEndPoint.Equals(remoteEP))
                        {
                            _tunnelProxy.Dispose();
                            _tunnelProxy = null;
                        }

                        if ((_tunnelProxy == null) || _tunnelProxy.IsBroken)
                        {
                            Socket socket = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                            await socket.ConnectAsync(remoteEP);

                            _tunnelProxy = new TunnelProxy(socket, remoteEP, _smtpOverTls, _ignoreCertificateErrors);
                        }

                        base.Host = _tunnelProxy.TunnelEndPoint.Address.ToString();
                        base.Port = _tunnelProxy.TunnelEndPoint.Port;
                    }
                    else
                    {
                        base.Host = hostIP.ToString();
                        base.Port = _port;
                    }

                    await base.SendMailAsync(message);
                }
                else
                {
                    EndPoint remoteEP = EndPointExtension.GetEndPoint(host, _port);

                    if ((_tunnelProxy != null) && !_tunnelProxy.RemoteEndPoint.Equals(remoteEP))
                    {
                        _tunnelProxy.Dispose();
                        _tunnelProxy = null;
                    }

                    if ((_tunnelProxy == null) || _tunnelProxy.IsBroken)
                        _tunnelProxy = await _proxy.CreateTunnelProxyAsync(remoteEP, _smtpOverTls, _ignoreCertificateErrors);

                    base.Host = _tunnelProxy.TunnelEndPoint.Address.ToString();
                    base.Port = _tunnelProxy.TunnelEndPoint.Port;

                    await base.SendMailAsync(message);
                }
            }
            else
            {
                await base.SendMailAsync(message);
            }
        }

        public new Task SendMailAsync(string from, string recipients, string subject, string body)
        {
            return SendMailAsync(new MailMessage(from, recipients, subject, body));
        }

        #endregion

        #region properties

        public string LocalHostName
        {
            get
            {
                if (_localHostName == null)
                    return null;

                return _localHostName.GetValue(this) as string;
            }
            set
            {
                _localHostName.SetValue(this, value);
            }
        }

        public IDnsClient DnsClient
        {
            get { return _dnsClient; }
            set { _dnsClient = value; }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public bool SmtpOverTls
        {
            get { return _smtpOverTls; }
            set { _smtpOverTls = value; }
        }

        public new string Host
        {
            get { return _host; }
            set { _host = value; }
        }

        public new int Port
        {
            get { return _port; }
            set { _port = value; }
        }

        public bool IgnoreCertificateErrors
        {
            get { return _ignoreCertificateErrors; }
            set { _ignoreCertificateErrors = value; }
        }

        #endregion
    }
}
