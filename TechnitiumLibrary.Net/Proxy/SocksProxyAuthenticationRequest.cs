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
using System.IO;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Proxy
{
    class SocksProxyAuthenticationRequest
    {
        #region variables

        const byte AUTH_VERSION = 1;

        byte _version;
        string _username;
        string _password;

        #endregion

        #region constructors

        private SocksProxyAuthenticationRequest()
        { }

        public SocksProxyAuthenticationRequest(string username, string password)
        {
            _version = AUTH_VERSION;
            _username = username;
            _password = password;
        }

        #endregion

        #region static

        public static async Task<SocksProxyAuthenticationRequest> ReadRequestAsync(Stream s)
        {
            SocksProxyAuthenticationRequest request = new SocksProxyAuthenticationRequest();

            byte[] buffer = new byte[256];
            await s.ReadBytesAsync(buffer, 0, 1);

            request._version = buffer[0];

            switch (request._version)
            {
                case AUTH_VERSION:
                    int length;

                    await s.ReadBytesAsync(buffer, 0, 1);
                    length = buffer[0];

                    await s.ReadBytesAsync(buffer, 0, length);
                    request._username = Encoding.ASCII.GetString(buffer, 0, length);

                    await s.ReadBytesAsync(buffer, 0, 1);
                    length = buffer[0];

                    await s.ReadBytesAsync(buffer, 0, length);
                    request._password = Encoding.ASCII.GetString(buffer, 0, length);
                    break;
            }

            return request;
        }

        #endregion

        #region public

        public async Task WriteToAsync(Stream s)
        {
            s.WriteByte(_version);

            byte[] username = Encoding.ASCII.GetBytes(_username);
            s.WriteByte(Convert.ToByte(username.Length));
            await s.WriteAsync(username);

            byte[] password = Encoding.ASCII.GetBytes(_password);
            s.WriteByte(Convert.ToByte(password.Length));
            await s.WriteAsync(password);
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public bool IsVersionSupported
        { get { return _version == AUTH_VERSION; } }

        public string Username
        { get { return _username; } }

        public string Password
        { get { return _password; } }

        #endregion
    }
}
