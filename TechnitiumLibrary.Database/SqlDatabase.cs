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
using System.Data.SqlClient;

namespace TechnitiumLibrary.Database
{
    public class SqlDatabase : TDatabase
    {
        #region constructor

        public SqlDatabase(SqlConnection Conn)
            : base(Conn)
        { }

        public SqlDatabase(string ConnectionString)
            : base(new SqlConnection(ConnectionString))
        { }

        #endregion

        #region static

        public static SqlDatabase CreateDatabase(SqlConnection sqlConn, string databaseName, string dbFileName, bool forAttach)
        {
            return CreateDatabase(new SqlDatabase(sqlConn), databaseName, dbFileName, forAttach);
        }

        public static SqlDatabase CreateDatabase(SqlDatabase DB, string databaseName, string dbFileName, bool forAttach)
        {
            DB.Command("CREATE DATABASE " + databaseName + " ON (FILENAME='" + dbFileName + "')" + (string)(forAttach ? " FOR ATTACH" : ""));
            DB.Command("USE " + databaseName);
            return DB;
        }

        public static SqlDatabase CreateDatabase(SqlConnection sqlConn, string databaseName)
        {
            return CreateDatabase(new SqlDatabase(sqlConn), databaseName);
        }

        public static SqlDatabase CreateDatabase(SqlDatabase DB, string databaseName)
        {
            DB.Command("CREATE DATABASE " + databaseName);
            DB.Command("USE " + databaseName);
            return DB;
        }

        public static SqlDatabase DropDatabase(SqlConnection sqlConn, string databaseName)
        {
            return DropDatabase(new SqlDatabase(sqlConn), databaseName);
        }

        public static SqlDatabase DropDatabase(SqlDatabase DB, string databaseName)
        {
            DB.Command("USE MASTER");
            DB.Command("ALTER DATABASE " + databaseName + " SET SINGLE_USER WITH ROLLBACK IMMEDIATE");
            DB.Command("DROP DATABASE " + databaseName);
            return DB;
        }

        public static SqlDatabase AttachDatabase(SqlConnection sqlConn, string databaseName, string dbFileName, string TxnLogFilename)
        {
            return AttachDatabase(new SqlDatabase(sqlConn), databaseName, dbFileName, TxnLogFilename);
        }

        public static SqlDatabase AttachDatabase(SqlDatabase DB, string databaseName, string dbFileName, string TxnLogFilename)
        {
            DB.Command("sp_attach_db '" + databaseName + "','" + dbFileName + "','" + TxnLogFilename + "'");
            DB.Command("USE " + databaseName);
            return DB;
        }

        public static void DetachDatabase(SqlConnection sqlConn, string databaseName)
        {
            DetachDatabase(new SqlDatabase(sqlConn), databaseName);
        }

        public static void DetachDatabase(SqlDatabase DB, string databaseName)
        {
            DB.Command("USE Master");
            DB.Command("sp_detach_db '" + databaseName + "'");
        }

        public static SqlConnection CreateConnectionNamedPipe(string Server, string InstanceName, string InitialCatalog, bool TransactionBindingExplicitUnbind = true, bool EnableMARS = false)
        {
            return new SqlConnection("Data Source=" + Server + (string)(string.IsNullOrEmpty(InstanceName) ? "" : "\\" + InstanceName) + "; Initial Catalog=" + InitialCatalog + "; Integrated Security=True;" + (string)(TransactionBindingExplicitUnbind ? " transaction binding=explicit Unbind;" : " transaction binding=implicit Unbind;") + (string)(EnableMARS ? " MultipleActiveResultSets=true;" : ""));
        }

        public static SqlConnection CreateConnectionAttachDBFile(string InstanceName, string AttachdbFileName, string Database, bool TransactionBindingExplicitUnbind = true, bool EnableMARS = false)
        {
            return new SqlConnection("Server=." + (string)(string.IsNullOrEmpty(InstanceName) ? "" : "\\" + InstanceName) + "; AttachdbFileName=" + AttachdbFileName + "; Database=" + Database + "; Integrated Security=True;" + (string)(TransactionBindingExplicitUnbind ? " transaction binding=explicit Unbind;" : " transaction binding=implicit Unbind;") + (string)(EnableMARS ? " MultipleActiveResultSets=true;" : ""));
            //Server=.\SQLExpress;AttachdbFileName=c:\asd\qwe\mydbfile.mdf;Database=dbname; Trusted_Connection=Yes;
        }

        public static SqlConnection CreateConnectionNamedPipe(string Server, string InstanceName, string InitialCatalog, string Username, string Password, bool TransactionBindingExplicitUnbind = true, bool EnableMARS = false)
        {
            return new SqlConnection("Data Source=" + Server + (string)(string.IsNullOrEmpty(InstanceName) ? "" : "\\" + InstanceName) + "; Initial Catalog=" + InitialCatalog + "; User Id=" + Username + "; Password=" + Password + ";" + (string)(TransactionBindingExplicitUnbind ? " transaction binding=explicit Unbind;" : " transaction binding=implicit Unbind;") + (string)(EnableMARS ? " MultipleActiveResultSets=true;" : ""));
        }

        public static SqlConnection CreateConnectionTCPIP(string Server, string InstanceName, string InitialCatalog, string Username, string Password, int Port = 1433, bool TransactionBindingExplicitUnbind = true, bool EnableMARS = false)
        {
            return new SqlConnection("Data Source=" + Server + (string)(string.IsNullOrEmpty(InstanceName) ? "" : "\\" + InstanceName) + "," + Port + "; Network Library=DBMSSOCN; Initial Catalog=" + InitialCatalog + "; User ID=" + Username + "; Password=" + Password + ";" + (string)(TransactionBindingExplicitUnbind ? " transaction binding=explicit Unbind;" : " transaction binding=implicit Unbind;") + (string)(EnableMARS ? " MultipleActiveResultSets=true;" : ""));
            //Data Source=190.190.200.100,1433;Network Library=DBMSSOCN;Initial Catalog=myDataBase;User ID=myUsername;Password=myPassword;
            //DBMSSOCN=TCP/IP. This is how to use TCP/IP instead of Named Pipes. At the end of the Data Source is the port to use. 1433 is the default port for SQL Server.
        }

        #endregion

        #region public

        public override DataTable TableQuery(IDbCommand comm)
        {
            using (SqlDataAdapter DA = new SqlDataAdapter((SqlCommand)comm))
            {
                DA.SelectCommand.Connection = (SqlConnection)_conn;
                DA.SelectCommand.Transaction = (SqlTransaction)_trxn;
                DataTable DT = new DataTable();
                DA.Fill(DT);
                return DT;
            }
        }

        #endregion
    }
}