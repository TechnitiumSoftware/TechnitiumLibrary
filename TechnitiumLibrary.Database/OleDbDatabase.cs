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

using System.Data;
using System.Data.OleDb;

namespace TechnitiumLibrary.Database
{
    public abstract class OleDbDatabase : TDatabase
    {
        #region constructor

        public OleDbDatabase(OleDbConnection Conn)
            : base(Conn)
        { }

        public OleDbDatabase(string ConnectionString)
            : base(new OleDbConnection(ConnectionString))
        { }

        #endregion

        #region public

        public override DataTable TableQuery(IDbCommand comm)
        {
            using (OleDbDataAdapter DA = new OleDbDataAdapter((OleDbCommand)comm))
            {
                DA.SelectCommand.Connection = (OleDbConnection)_conn;
                DA.SelectCommand.Transaction = (OleDbTransaction)_trxn;
                DataTable DT = new DataTable();
                DA.Fill(DT);
                return DT;
            }
        }

        #endregion
    }
}