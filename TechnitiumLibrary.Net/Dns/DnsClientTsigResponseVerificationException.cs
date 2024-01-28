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
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsClientTsigResponseVerificationException : DnsClientException
    {
        #region variables

        readonly DnsResponseCode _rCode;
        readonly DnsTsigError _error;

        #endregion

        #region constructors

        public DnsClientTsigResponseVerificationException(DnsResponseCode rCode, DnsTsigError error)
            : base("Response failed TSIG signature verification (Client RCODE=" + rCode.ToString() + ", Client TSIG Error=" + error.ToString() + ").")
        {
            _rCode = rCode;
            _error = error;
        }

        public DnsClientTsigResponseVerificationException(DnsResponseCode rCode, DnsTsigError error, string message)
            : base(message)
        {
            _rCode = rCode;
            _error = error;
        }

        public DnsClientTsigResponseVerificationException(DnsResponseCode rCode, DnsTsigError error, string message, Exception innerException)
            : base(message, innerException)
        {
            _rCode = rCode;
            _error = error;
        }

        #endregion

        #region properties

        public DnsResponseCode RCODE
        { get { return _rCode; } }

        public DnsTsigError Error
        { get { return _error; } }

        #endregion
    }
}
