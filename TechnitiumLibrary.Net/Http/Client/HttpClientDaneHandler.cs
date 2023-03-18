/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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

using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Http.Client
{
    public class HttpClientDaneHandler : DelegatingHandler
    {
        #region variables

        readonly DnsClient _dnsClient;

        #endregion

        #region constructor

        public HttpClientDaneHandler(SocketsHttpHandler innerHandler, DnsClient dnsClient = null)
            : base(innerHandler)
        {
            _dnsClient = dnsClient ?? new DnsClient();
            _dnsClient.DnssecValidation = true;

            innerHandler.SslOptions.RemoteCertificateValidationCallback += delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                _dnsClient.ValidateDaneAsync(sender as SslStream, certificate, chain, sslPolicyErrors).Sync();
                return true;
            };
        }

        #endregion
    }
}
