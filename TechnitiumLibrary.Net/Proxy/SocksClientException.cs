/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Proxy
{
    public class SocksClientException : NetProxyException
    {
        #region variables

        readonly SocksReplyCode _replyCode;

        #endregion

        #region constructors

        public SocksClientException()
            : base()
        { }

        public SocksClientException(string message)
            : base(message)
        { }

        public SocksClientException(string message, SocksReplyCode replyCode)
            : base(message)
        {
            _replyCode = replyCode;
        }

        public SocksClientException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected SocksClientException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion

        #region properties

        public SocksReplyCode ReplyCode
        { get { return _replyCode; } }

        #endregion
    }
}
