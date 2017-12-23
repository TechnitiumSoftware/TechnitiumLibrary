/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Tor
{
    public class TorHiddenServiceInfo
    {
        #region variables

        string _serviceId;
        string _privateKey;
        string _clientBasicAuthUser;
        string _clientBasicAuthCookie;

        #endregion

        #region constructor

        internal TorHiddenServiceInfo(StreamReader sR)
        {
            while (true)
            {
                string response = sR.ReadLine();
                if (response == null)
                    break;

                if (!response.StartsWith("250"))
                    throw new TorControllerException("Server returned: " + response);

                if (response.StartsWith("250 "))
                    break;

                if (response.StartsWith("250-ServiceID=", StringComparison.CurrentCultureIgnoreCase))
                {
                    _serviceId = response.Substring(14);
                }
                else if (response.StartsWith("250-PrivateKey=", StringComparison.CurrentCultureIgnoreCase))
                {
                    _privateKey = response.Substring(15);
                }
                else if (response.StartsWith("250-ClientAuth=", StringComparison.CurrentCultureIgnoreCase))
                {
                    string[] parts = response.Substring(15).Split(':');
                    if (parts.Length == 2)
                    {
                        _clientBasicAuthUser = parts[0];
                        _clientBasicAuthCookie = parts[1];
                    }
                }
            }
        }

        #endregion

        #region properties

        public string ServiceId
        { get { return _serviceId; } }

        public string PrivateKey
        { get { return _privateKey; } }

        public string ClientBasicAuthenticationUsername
        { get { return _clientBasicAuthUser; } }

        public string ClientBasicAuthenticationCookie
        { get { return _clientBasicAuthCookie; } }

        #endregion
    }
}