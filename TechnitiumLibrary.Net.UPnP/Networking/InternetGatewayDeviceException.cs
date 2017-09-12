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

namespace TechnitiumLibrary.Net.UPnP.Networking
{
    [System.Serializable()]
    public class InternetGatewayDeviceException : UPnPException
    {
        #region variables

        int _errorCode;

        #endregion

        #region constructor

        public InternetGatewayDeviceException()
        { }

        public InternetGatewayDeviceException(string message)
            : base(message)
        { }

        public InternetGatewayDeviceException(int errorCode, string message)
            : base(message)
        {
            _errorCode = errorCode;
        }

        public InternetGatewayDeviceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected InternetGatewayDeviceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion

        #region properties

        public int ErrorCode
        { get { return _errorCode; } }

        #endregion
    }
}