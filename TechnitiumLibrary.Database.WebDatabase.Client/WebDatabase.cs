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
using System.Collections.Specialized;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Database.WebDatabase.Client
{
    public class WebDatabase : IDisposable
    {
        #region variables

        Uri _webDatabaseUri;
        WebClientEx _webClient;

        bool _inTransaction;

        #endregion

        #region constructor

        public WebDatabase(Uri webDatabaseUri, string sharedSecret)
        {
            _webDatabaseUri = webDatabaseUri;
            _webClient = new WebClientEx();

            _webClient.QueryString.Add("cmd", "login");
            _webClient.QueryString.Add("code", BitConverter.ToString(HashAlgorithm.Create("SHA1").ComputeHash(Encoding.ASCII.GetBytes(DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm") + sharedSecret))).Replace("-", "").ToLower());

            byte[] buffer = _webClient.DownloadData(_webDatabaseUri);

            using (BinaryReader bR = new BinaryReader(new MemoryStream(buffer)))
            {
                int errorCode = bR.ReadInt32();
                if (errorCode != 0)
                {
                    string message = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));
                    string remoteStackTrace = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));

                    throw new WebDatabaseException(message, errorCode, remoteStackTrace);
                }
            }
        }

        public WebDatabase(Uri webDatabaseUri, WebClientEx webClient)
        {
            _webDatabaseUri = webDatabaseUri;
            _webClient = webClient;
        }

        #endregion

        #region public

        public void BeginTransaction()
        {
            if (_inTransaction)
                throw new WebDatabaseException("WebDatabase is already in a transaction.");

            Command(new WebSqlCommand("BEGIN TRANSACTION;"));
            _inTransaction = true;
        }

        public void Commit()
        {
            if (!_inTransaction)
                throw new WebDatabaseException("WebDatabase is not in a transaction.");

            Command(new WebSqlCommand("COMMIT;"));
            _inTransaction = false;
        }

        public void Rollback()
        {
            if (!_inTransaction)
                throw new WebDatabaseException("WebDatabase is not in a transaction.");

            Command(new WebSqlCommand("ROLLBACK;"));
            _inTransaction = false;
        }

        public int Command(string sqlQuery)
        {
            return Command(new WebSqlCommand(sqlQuery));
        }

        public int Command(WebSqlCommand sqlCmd)
        {
            if (sqlCmd.SqlQuery.StartsWith("SELECT", StringComparison.CurrentCultureIgnoreCase))
                throw new WebDatabaseException("SELECT query is not supported in WebDatabase Command function.");

            byte[] buffer;

            try
            {
                _webClient.QueryString.Clear();
                buffer = _webClient.UploadValues(_webDatabaseUri, "POST", GetPostValues(sqlCmd));
            }
            catch (Exception ex)
            {
                throw new WebDatabaseException(ex.Message, ex, -1);
            }

            using (BinaryReader bR = new BinaryReader(new MemoryStream(buffer)))
            {
                int errorCode = bR.ReadInt32();
                if (errorCode != 0)
                {
                    string message = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));
                    string remoteStackTrace = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));

                    throw new WebDatabaseException(message, errorCode, remoteStackTrace);
                }

                return bR.ReadInt32();
            }
        }

        public int Command(string sqlQuery, ushort maxRetries, int retryInterval = 30000)
        {
            return Command(new WebSqlCommand(sqlQuery), maxRetries, retryInterval);
        }

        public int Command(WebSqlCommand sqlCmd, ushort maxRetries, int retryInterval = 30000)
        {
            int retryCount = 1;

            do
            {
                try
                {
                    return Command(sqlCmd);
                }
                catch
                {
                    retryCount += 1;

                    if (retryCount > maxRetries)
                        throw;

                    Thread.Sleep(retryInterval);
                }
            } while (true);
        }

        public WebDataTable TableQuery(string sqlQuery)
        {
            return TableQuery(new WebSqlCommand(sqlQuery));
        }

        public WebDataTable TableQuery(WebSqlCommand sqlCmd)
        {
            if (!sqlCmd.SqlQuery.StartsWith("SELECT", StringComparison.CurrentCultureIgnoreCase))
                throw new WebDatabaseException("Only SELECT query is supported in WebDatabase TableQuery function.");

            if (_inTransaction)
                throw new WebDatabaseException("SELECT query not supported while WebDatabase is in a transaction.");

            byte[] buffer;

            try
            {
                _webClient.QueryString.Clear();
                buffer = _webClient.UploadValues(_webDatabaseUri, "POST", GetPostValues(sqlCmd));
            }
            catch (Exception ex)
            {
                throw new WebDatabaseException(ex.Message, ex, -1);
            }

            using (BinaryReader bR = new BinaryReader(new MemoryStream(buffer)))
            {
                int errorCode = bR.ReadInt32();
                if (errorCode != 0)
                {
                    string message = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));
                    string remoteStackTrace = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadInt32()));

                    throw new WebDatabaseException(message, errorCode, remoteStackTrace);
                }

                WebDataTable DT = new WebDataTable();

                #region read column names

                byte colCount = bR.ReadByte();
                for (int col = 0; col < colCount; col++)
                    DT.Columns.Add(Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte())));

                #endregion

                #region read row data

                int rowCount = bR.ReadInt32();

                for (int row = 0; row < rowCount; row++)
                {
                    WebDataRow DR = new WebDataRow(DT);

                    for (int col = 0; col < colCount; col++)
                        DR.Items.Add(new WebDbDataItem(bR.BaseStream));

                    DT.Rows.Add(DR);
                }

                #endregion

                return DT;
            }
        }

        public WebDataTable TableQuery(string sqlQuery, ushort maxRetries, int retryInterval = 30000)
        {
            return TableQuery(new WebSqlCommand(sqlQuery), maxRetries, retryInterval);
        }

        public WebDataTable TableQuery(WebSqlCommand sqlCmd, ushort maxRetries, int retryInterval = 30000)
        {
            int retryCount = 1;
            do
            {
                try
                {
                    return TableQuery(sqlCmd);
                }
                catch
                {
                    retryCount += 1;

                    if (retryCount > maxRetries)
                        throw;

                    Thread.Sleep(retryInterval);
                }
            } while (true);
        }

        #endregion

        #region private

        private NameValueCollection GetPostValues(WebSqlCommand sqlCmd)
        {
            NameValueCollection Values = new NameValueCollection();

            Values.Add("q", sqlCmd.SqlQuery);

            for (int i = 0; i < sqlCmd.Parameters.Count; i++)
                Values.Add(sqlCmd.Parameters.Keys[i], Convert.ToBase64String(((WebDbDataItem)sqlCmd.Parameters[i]).ToArray()));

            return Values;
        }

        #endregion

        #region properties

        public Uri WebDatabaseUri
        { get { return _webDatabaseUri; } }

        public WebClientEx WebClient
        { get { return _webClient; } }

        public bool InTransaction
        { get { return _inTransaction; } }

        #endregion

        #region IDisposable

        ~WebDatabase()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (_inTransaction)
                        Rollback();

                    _webClient.QueryString.Clear();
                    _webClient.QueryString.Add("cmd", "logout");
                    _webClient.DownloadData(_webDatabaseUri);

                    _webClient.Dispose();
                }

                disposed = true;
            }
        }

        #endregion
    }
}