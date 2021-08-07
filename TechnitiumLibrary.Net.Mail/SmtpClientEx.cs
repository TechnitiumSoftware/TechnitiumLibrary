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
        static bool _ignoreCertificateErrorsForProxy;

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
            if (sender is SmtpClientEx smtpClient)
            {
                if (smtpClient._ignoreCertificateErrors)
                    return true;

                switch (sslPolicyErrors)
                {
                    case SslPolicyErrors.None:
                        return true;

                    case SslPolicyErrors.RemoteCertificateNameMismatch:
                        return smtpClient._proxy != null; //trusting name mismatch when proxy is set

                    default:
                        return false;
                }
            }

            if (sender is SslStream sslStream && IPAddress.TryParse(sslStream.TargetHostName, out IPAddress address) && IPAddress.IsLoopback(address))
            {
                if (_ignoreCertificateErrorsForProxy)
                    return true;

                switch (sslPolicyErrors)
                {
                    case SslPolicyErrors.None:
                    case SslPolicyErrors.RemoteCertificateNameMismatch: //trusting name mismatch for loopback tunnel proxy
                        return true;

                    default:
                        return false;
                }
            }

            if (_existingServerCertificateValidationCallback != null)
                return _existingServerCertificateValidationCallback(sender, certificate, chain, sslPolicyErrors);

            return sslPolicyErrors == SslPolicyErrors.None;
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

                    IReadOnlyList<string> mxDomains = await Dns.DnsClient.ResolveMXAsync(_dnsClient, message.To[0].Host);
                    if (mxDomains.Count > 0)
                        host = mxDomains[0];
                    else
                        host = message.To[0].Host;

                    _port = 25;
                    Credentials = null;
                }

                if (_proxy == null)
                {
                    if (_smtpOverTls)
                    {
                        EndPoint remoteEP = EndPointExtension.GetEndPoint(host, _port);

                        if ((_tunnelProxy != null) && !_tunnelProxy.RemoteEndPoint.Equals(remoteEP))
                        {
                            _tunnelProxy.Dispose();
                            _tunnelProxy = null;
                        }

                        if ((_tunnelProxy == null) || _tunnelProxy.IsBroken)
                            _tunnelProxy = await TunnelProxy.CreateTunnelProxyAsync(remoteEP, true, _ignoreCertificateErrors);

                        base.Host = _tunnelProxy.TunnelEndPoint.Address.ToString();
                        base.Port = _tunnelProxy.TunnelEndPoint.Port;
                    }
                    else
                    {
                        base.Host = host;
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

        public static bool IgnoreCertificateErrorsForProxy
        {
            get { return _ignoreCertificateErrorsForProxy; }
            set { _ignoreCertificateErrorsForProxy = value; }
        }

        #endregion
    }
}
