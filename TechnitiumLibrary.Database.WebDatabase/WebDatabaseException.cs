/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Database.WebDatabase
{
    [System.Serializable()]
    public class WebDatabaseException : Exception
    {
        int _errorCode;
        string _remoteStackTrace;


        public WebDatabaseException()
            : base()
        { }

        public WebDatabaseException(string message, int errorCode = 0, string remoteStackTrace = null)
            : base(message)
        {
            _errorCode = errorCode;
            _remoteStackTrace = remoteStackTrace;
        }

        public WebDatabaseException(string message, Exception innerException, int errorCode = 0, string remoteStackTrace = null)
            : base(message, innerException)
        {
            _errorCode = errorCode;
            _remoteStackTrace = remoteStackTrace;
        }

        public int ErrorCode
        { get { return _errorCode; } }

        public string RemoteStackTrace
        { get { return _remoteStackTrace; } }
    }
}