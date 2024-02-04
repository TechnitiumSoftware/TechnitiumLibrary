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

using System.IO;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Proxy
{
    enum SocksProxyAuthenticationStatus : byte
    {
        Success = 0,
        Failure = 1
    }

    class SocksProxyAuthenticationReply
    {
        #region variables

        const byte AUTH_VERSION = 1;

        byte _version;
        SocksProxyAuthenticationStatus _status;

        #endregion

        #region constructors

        private SocksProxyAuthenticationReply()
        { }

        public SocksProxyAuthenticationReply(SocksProxyAuthenticationStatus status)
        {
            _version = AUTH_VERSION;
            _status = status;
        }

        #endregion

        #region static

        public static async Task<SocksProxyAuthenticationReply> ReadRequestAsync(Stream s)
        {
            SocksProxyAuthenticationReply reply = new SocksProxyAuthenticationReply();

            byte[] buffer = new byte[2];
            await s.ReadExactlyAsync(buffer);

            reply._version = buffer[0];
            reply._status = buffer[1] == 0 ? SocksProxyAuthenticationStatus.Success : SocksProxyAuthenticationStatus.Failure;

            return reply;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            byte[] buffer = new byte[2];

            buffer[0] = _version;
            buffer[1] = (byte)_status;

            await s.WriteAsync(buffer);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == AUTH_VERSION; } }

        public SocksProxyAuthenticationStatus Status
        { get { return _status; } }

        #endregion
    }
}
