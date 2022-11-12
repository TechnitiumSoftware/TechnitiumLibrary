/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Http
{
    public class HttpClientDaneHandler : HttpMessageHandler
    {
        #region variables

        readonly DnsClient _dnsClient;
        readonly HttpMessageInvoker _messageInvoker;

        #endregion

        #region constructor

        public HttpClientDaneHandler()
        {
            _dnsClient = new DnsClient();
            _dnsClient.DnssecValidation = true;

            SocketsHttpHandler httpHandler = new SocketsHttpHandler();

            httpHandler.SslOptions.RemoteCertificateValidationCallback += delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                _dnsClient.ValidateDaneAsync(sender as SslStream, certificate, chain, sslPolicyErrors).Sync();
                return true;
            };

            _messageInvoker = new HttpMessageInvoker(httpHandler);
        }

        #endregion

        #region protected

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _messageInvoker.SendAsync(request, cancellationToken);
        }

        #endregion
    }
}
