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

using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    class SocksProxyNegotiationReply
    {
        #region variables

        const byte SOCKS_VERSION = 5;

        byte _version;
        SocksProxyAuthenticationMethod _method;

        #endregion

        #region constructors

        private SocksProxyNegotiationReply()
        { }

        public SocksProxyNegotiationReply(SocksProxyAuthenticationMethod method)
        {
            _version = SOCKS_VERSION;
            _method = method;
        }

        #endregion

        #region static

        public static async Task<SocksProxyNegotiationReply> ReadRequestAsync(Stream s)
        {
            SocksProxyNegotiationReply reply = new SocksProxyNegotiationReply();

            byte[] buffer = new byte[2];
            await s.ReadBytesAsync(buffer, 0, buffer.Length);

            reply._version = buffer[0];
            reply._method = (SocksProxyAuthenticationMethod)buffer[1];

            return reply;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            byte[] buffer = new byte[2];

            buffer[0] = _version;
            buffer[1] = (byte)_method;

            await s.WriteAsync(buffer, 0, buffer.Length);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == SOCKS_VERSION; } }

        public SocksProxyAuthenticationMethod Method
        { get { return _method; } }

        #endregion
    }
}
