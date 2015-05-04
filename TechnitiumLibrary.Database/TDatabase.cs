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
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.OleDb;
using System.Data.SqlClient;
using System.Diagnostics;

namespace TechnitiumLibrary.Database
{
    public abstract class TDatabase : IDisposable
    {
        #region variables

        protected IDbConnection _conn;
        protected IDbTransaction _trxn;

        protected bool _committed;

        #endregion

        #region constructor

        public TDatabase(IDbConnection Conn)
        {
            _conn = Conn;

            if (_conn.State == ConnectionState.Closed)
                _conn.Open();

            _committed = true;
        }

        #endregion

        #region public

        public void Commit()
        {
            _trxn.Commit();
            _committed = true;
        }

        public void Rollback()
        {
            _trxn.Rollback();
            _committed = true;
        }

        public void BeginTransaction()
        {
            if (!_committed)
                throw new TDatabaseException("Current transaction still exists and not committed.");

            _trxn = _conn.BeginTransaction();
            _committed = false;
        }

        public DataTable TableQuery(string SQLQuery)
        {
            IDbCommand comm = _conn.CreateCommand();
            comm.CommandText = SQLQuery;

            return TableQuery(comm);
        }

        public abstract DataTable TableQuery(IDbCommand comm);

        public IDataReader ReaderQuery(string SQLQuery)
        {
            IDbCommand comm = _conn.CreateCommand();
            comm.CommandText = SQLQuery;
            comm.Transaction = _trxn;
            return comm.ExecuteReader();
        }

        public IDataReader ReaderQuery(IDbCommand comm)
        {
            comm.Connection = _conn;
            comm.Transaction = _trxn;
            return comm.ExecuteReader();
        }

        public int Command(string SQLQuery)
        {
            IDbCommand comm = _conn.CreateCommand();
            comm.CommandText = SQLQuery;
            comm.Transaction = _trxn;
            return comm.ExecuteNonQuery();
        }

        public int Command(IDbCommand comm)
        {
            comm.Connection = _conn;
            comm.Transaction = _trxn;
            return comm.ExecuteNonQuery();
        }

        #endregion

        #region properties

        public IDbConnection Connection
        { get { return _conn; } }

        public bool InTransaction
        { get { return !_committed; } }

        #endregion

        #region IDisposable

        ~TDatabase()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    try
                    {
                        if (!_committed)
                        {
                            _trxn.Rollback();
                        }
                    }
                    catch (Exception)
                    { }

                    try
                    {
                        _conn.Close();
                    }
                    catch
                    { }
                }

                disposed = true;
            }
        }

        #endregion
    }

    [System.Serializable()]
    public class TDatabaseException : Exception
    {
        #region constructor

        public TDatabaseException()
        { }

        public TDatabaseException(string Message)
            : base(Message)
        { }

        public TDatabaseException(string Message, Exception innerException)
            : base(Message, innerException)
        { }

        protected TDatabaseException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}