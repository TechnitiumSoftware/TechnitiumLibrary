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
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    public enum SocksProxyAuthenticationMethod : byte
    {
        NoAuthenticationRequired = 0x0,
        GSSAPI = 0x01,
        UsernamePassword = 0x2,
        NoAcceptableMethods = 0xff
    }

    class SocksProxyNegotiationRequest
    {
        #region variables

        const byte SOCKS_VERSION = 5;

        byte _version;
        SocksProxyAuthenticationMethod[] _methods;

        #endregion

        #region constructors

        private SocksProxyNegotiationRequest()
        { }

        public SocksProxyNegotiationRequest(SocksProxyAuthenticationMethod[] methods)
        {
            _version = SOCKS_VERSION;
            _methods = methods;
        }

        #endregion

        #region static

        public static async Task<SocksProxyNegotiationRequest> ReadRequestAsync(Stream s)
        {
            SocksProxyNegotiationRequest request = new SocksProxyNegotiationRequest();

            byte[] buffer = new byte[255];
            await s.ReadBytesAsync(buffer, 0, 2);

            request._version = buffer[0];

            switch (request._version)
            {
                case SOCKS_VERSION:
                    int nMethods = buffer[1];
                    await s.ReadBytesAsync(buffer, 0, nMethods);

                    request._methods = new SocksProxyAuthenticationMethod[nMethods];

                    for (int i = 0; i < nMethods; i++)
                        request._methods[i] = (SocksProxyAuthenticationMethod)buffer[i];

                    break;
            }

            return request;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            byte[] buffer = new byte[2 + _methods.Length];

            buffer[0] = _version;
            buffer[1] = Convert.ToByte(_methods.Length);

            Array.Copy(_methods, 0, buffer, 2, _methods.Length);

            await s.WriteAsync(buffer);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == SOCKS_VERSION; } }

        public SocksProxyAuthenticationMethod[] Methods
        { get { return _methods; } }

        #endregion
    }
}
