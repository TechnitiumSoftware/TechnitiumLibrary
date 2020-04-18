/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
    public class SocksProxyAuthenticationFailedException : NetProxyAuthenticationFailedException
    {
        #region variables

        readonly SocksReplyCode _replyCode;

        #endregion

        #region constructors

        public SocksProxyAuthenticationFailedException()
            : base()
        { }

        public SocksProxyAuthenticationFailedException(string message)
            : base(message)
        { }

        public SocksProxyAuthenticationFailedException(string message, SocksReplyCode replyCode)
            : base(message)
        {
            _replyCode = replyCode;
        }

        public SocksProxyAuthenticationFailedException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected SocksProxyAuthenticationFailedException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion

        #region properties

        public SocksReplyCode ReplyCode
        { get { return _replyCode; } }

        #endregion
    }
}
