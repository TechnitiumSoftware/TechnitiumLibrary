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
using System.Data.SqlClient;

namespace TechnitiumLibrary.Database
{
    public enum SqlConnectionProtocol
    {
        NamedPipe = 0,
        TCPIP = 1
    }

    public class SqlConnectionManager
    {
        #region variables

        private string _server;
        private string _instanceName;
        private string _databaseName;
        private SqlConnectionProtocol _protocol;
        private string _username;
        private string _password;

        #endregion

        #region constructor

        private SqlConnectionManager()
        { }

        #endregion

        #region static

        public static SqlConnectionManager CreateNamedPipe(string server, string instanceName, string databaseName)
        {
            SqlConnectionManager Obj = new SqlConnectionManager();

            Obj._server = server;
            Obj._instanceName = instanceName;
            Obj._databaseName = databaseName;
            Obj._protocol = SqlConnectionProtocol.NamedPipe;

            return Obj;
        }

        public static SqlConnectionManager CreateTCPIP(string server, string instanceName, string databaseName, string username, string password)
        {
            SqlConnectionManager Obj = new SqlConnectionManager();

            Obj._server = server;
            Obj._instanceName = instanceName;
            Obj._databaseName = databaseName;
            Obj._protocol = SqlConnectionProtocol.TCPIP;
            Obj._username = username;
            Obj._password = password;

            return Obj;
        }

        #endregion

        #region public

        public SqlConnection GetSqlDBConnection()
        {
            switch (_protocol)
            {
                case SqlConnectionProtocol.NamedPipe:
                    return SqlDatabase.CreateConnectionNamedPipe(_server, _instanceName, _databaseName);

                case SqlConnectionProtocol.TCPIP:
                    return SqlDatabase.CreateConnectionTCPIP(_server, _instanceName, _databaseName, _username, _password);

                default:
                    throw new Exception("Invalid protocol specified.");
            }
        }

        #endregion

        #region properties

        public string Server
        { get { return _server; } }

        public string InstanceName
        { get { return _instanceName; } }

        public string DatabaseName
        { get { return _databaseName; } }

        public SqlConnectionProtocol Protocol
        { get { return _protocol; } }

        public string Username
        { get { return _username; } }

        #endregion
    }
}