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
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Http.Client
{
    public class HttpClientRetryHandler : DelegatingHandler
    {
        #region variables

        int _retries = 3;

        #endregion

        #region constructor

        public HttpClientRetryHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        { }

        #endregion

        #region protected

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int retry = 0;

            while (retry++ < _retries)
            {
                try
                {
                    return await base.SendAsync(request, cancellationToken);
                }
                catch (HttpRequestException ex)
                {
                    if (ex.InnerException is SocketException ex2)
                    {
                        switch (ex2.SocketErrorCode)
                        {
                            case SocketError.ConnectionRefused:
                            case SocketError.HostNotFound:
                                throw;
                        }
                    }

                    if (retry >= _retries)
                        throw;
                }
            }

            throw new InvalidOperationException();
        }

        #endregion

        #region properties

        public int Retries
        {
            get { return _retries; }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException(nameof(Retries), "HttpClient retries value cannot be less than 1.");

                _retries = value;
            }
        }

        #endregion
    }
}
