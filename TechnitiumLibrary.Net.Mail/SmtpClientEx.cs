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
using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Mail
{
    public class SmtpClientEx : SmtpClient
    {
        #region variables

        readonly static RemoteCertificateValidationCallback _existingServerCertificateValidationCallback;
        readonly static AsyncLocal<SmtpClientEx> _sendingClient = new AsyncLocal<SmtpClientEx>();
        static bool _ignoreCertificateErrorsForProxy;

        readonly static FieldInfo _localHostName = typeof(SmtpClient).GetField("_clientDomain", BindingFlags.Instance | BindingFlags.NonPublic);
        IDnsClient _dnsClient;
        NetProxy _proxy;
        bool _smtpOverTls;
        string _host;
        int _port = 25;
        bool _ignoreCertificateErrors;

        TunnelProxy _tunnelProxy;
        bool _tunnelUsesSsl;
        bool _tunnelIgnoresCertificateErrors;
        NetProxy _tunnelProxyOwner;

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
            SmtpClientEx smtpClient = _sendingClient.Value;
            if (smtpClient is null)
                smtpClient = sender as SmtpClientEx;

            if (smtpClient is not null)
            {
                if (smtpClient._ignoreCertificateErrors)
                    return true;

                bool currentTunnel = IsCurrentSmtpTunnel(smtpClient, sender);

                switch (sslPolicyErrors)
                {
                    case SslPolicyErrors.None:
                        return true;

                    case SslPolicyErrors.RemoteCertificateNameMismatch:
                        return currentTunnel;

                    default:
                        return _ignoreCertificateErrorsForProxy && currentTunnel;
                }
            }

            if (_existingServerCertificateValidationCallback != null)
                return _existingServerCertificateValidationCallback(sender, certificate, chain, sslPolicyErrors);

            return sslPolicyErrors == SslPolicyErrors.None;
        }

        static bool IsCurrentSmtpTunnel(SmtpClientEx smtpClient, object sender)
        {
            if ((smtpClient._tunnelProxy is null) || (sender is not SslStream sslStream))
                return false;

            if (!IPAddress.TryParse(sslStream.TargetHostName, out IPAddress address))
                return false;

            return address.Equals(smtpClient._tunnelProxy.TunnelEndPoint.Address);
        }

        #endregion

        #region public

        public void SetRandomLocalHostName()
        {
            Span<byte> buffer = stackalloc byte[4];
            RandomNumberGenerator.Fill(buffer);

            LocalHostName = Convert.ToHexString(buffer);
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

        sealed class RecipientGroup
        {
            public readonly List<MailAddress> To = new List<MailAddress>();
            public readonly List<MailAddress> Cc = new List<MailAddress>();
            public readonly List<MailAddress> Bcc = new List<MailAddress>();
        }

        public new async Task SendMailAsync(MailMessage message)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            SmtpClientEx previous = _sendingClient.Value;
            _sendingClient.Value = this;

            try
            {
                if ((message.To.Count == 0) && (message.CC.Count == 0) && (message.Bcc.Count == 0))
                    throw new ArgumentException("Message does not contain receipent email address.");

                if (DeliveryMethod != SmtpDeliveryMethod.Network)
                {
                    await base.SendMailAsync(message);
                    return;
                }

                if (string.IsNullOrEmpty(_host))
                {
                    await SendToRecipientDomainsAsync(message);
                    return;
                }

                await DeliverAsync(message, _host, _port);
            }
            finally
            {
                _sendingClient.Value = previous;
            }
        }

        async Task SendToRecipientDomainsAsync(MailMessage message)
        {
            if (_dnsClient == null)
                _dnsClient = new DnsClient() { Proxy = _proxy };

            Dictionary<string, RecipientGroup> groups = new Dictionary<string, RecipientGroup>(StringComparer.OrdinalIgnoreCase);

            foreach (MailAddress address in message.To)
                AddRecipient(groups, address, 0);

            foreach (MailAddress address in message.CC)
                AddRecipient(groups, address, 1);

            foreach (MailAddress address in message.Bcc)
                AddRecipient(groups, address, 2);

            MailAddress[] originalTo = new MailAddress[message.To.Count];
            MailAddress[] originalCc = new MailAddress[message.CC.Count];
            MailAddress[] originalBcc = new MailAddress[message.Bcc.Count];
            message.To.CopyTo(originalTo, 0);
            message.CC.CopyTo(originalCc, 0);
            message.Bcc.CopyTo(originalBcc, 0);

            ICredentialsByHost savedCredentials = Credentials;
            Credentials = null;

            try
            {
                foreach (KeyValuePair<string, RecipientGroup> item in groups)
                {
                    message.To.Clear();
                    message.CC.Clear();
                    message.Bcc.Clear();

                    foreach (MailAddress address in item.Value.To)
                        message.To.Add(address);

                    foreach (MailAddress address in item.Value.Cc)
                        message.CC.Add(address);

                    foreach (MailAddress address in item.Value.Bcc)
                        message.Bcc.Add(address);

                    await DeliverToDomainAsync(message, item.Key);
                }
            }
            finally
            {
                Credentials = savedCredentials;

                message.To.Clear();
                message.CC.Clear();
                message.Bcc.Clear();

                foreach (MailAddress address in originalTo)
                    message.To.Add(address);

                foreach (MailAddress address in originalCc)
                    message.CC.Add(address);

                foreach (MailAddress address in originalBcc)
                    message.Bcc.Add(address);
            }
        }

        static void AddRecipient(Dictionary<string, RecipientGroup> groups, MailAddress address, int field)
        {
            if ((address is null) || string.IsNullOrEmpty(address.Host))
                throw new ArgumentException("Message does not contain receipent email address.");

            if (!groups.TryGetValue(address.Host, out RecipientGroup group))
            {
                group = new RecipientGroup();
                groups.Add(address.Host, group);
            }

            switch (field)
            {
                case 0:
                    group.To.Add(address);
                    break;

                case 1:
                    group.Cc.Add(address);
                    break;

                default:
                    group.Bcc.Add(address);
                    break;
            }
        }

        async Task DeliverToDomainAsync(MailMessage message, string domain)
        {
            IReadOnlyList<string> mxDomains = await Dns.DnsClient.ResolveMXAsync(_dnsClient, domain);
            if (mxDomains.Count == 0)
            {
                await DeliverAsync(message, domain, 25);
                return;
            }

            Exception lastError = null;

            foreach (string mxDomain in mxDomains)
            {
                try
                {
                    await DeliverAsync(message, mxDomain, 25);
                    return;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            throw lastError;
        }

        async Task DeliverAsync(MailMessage message, string host, int port)
        {
            if ((_proxy == null) && !_smtpOverTls)
            {
                base.Host = host;
                base.Port = port;
            }
            else
            {
                await EnsureTunnelAsync(EndPointExtensions.GetEndPoint(host, port), _smtpOverTls, _ignoreCertificateErrors, _proxy);
            }

            await base.SendMailAsync(message);
        }

        async Task EnsureTunnelAsync(EndPoint remoteEP, bool useSsl, bool ignoreCertificateErrors, NetProxy proxy)
        {
            bool sameTunnel = (_tunnelProxy != null)
                && !_tunnelProxy.IsBroken
                && _tunnelProxy.RemoteEndPoint.Equals(remoteEP)
                && (_tunnelUsesSsl == useSsl)
                && (_tunnelIgnoresCertificateErrors == ignoreCertificateErrors)
                && ReferenceEquals(_tunnelProxyOwner, proxy);

            if (!sameTunnel)
            {
                if (_tunnelProxy != null)
                {
                    _tunnelProxy.Dispose();
                    _tunnelProxy = null;
                }

                if (proxy == null)
                    _tunnelProxy = await TunnelProxy.CreateTunnelProxyAsync(remoteEP, useSsl, ignoreCertificateErrors);
                else
                    _tunnelProxy = await proxy.CreateTunnelProxyAsync(remoteEP, useSsl, ignoreCertificateErrors);

                _tunnelUsesSsl = useSsl;
                _tunnelIgnoresCertificateErrors = ignoreCertificateErrors;
                _tunnelProxyOwner = proxy;
            }

            base.Host = _tunnelProxy.TunnelEndPoint.Address.ToString();
            base.Port = _tunnelProxy.TunnelEndPoint.Port;
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
