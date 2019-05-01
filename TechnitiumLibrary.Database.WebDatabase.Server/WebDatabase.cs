/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.SessionState;

namespace TechnitiumLibrary.Database.WebDatabase.Server
{
    public static class WebDatabase
    {
        private static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        public static void ProcessRequest(HttpRequest request, HttpResponse response, HttpSessionState session, SqlConnection conn, string sharedSecret)
        {
            response.ContentType = "application/octet-stream";

            try
            {
                switch (request.QueryString["cmd"])
                {
                    case "challenge":
                        byte[] buffer = new byte[32];
                        _rnd.GetBytes(buffer);

                        session["challenge"] = buffer;
                        response.OutputStream.Write(new byte[4], 0, 4);
                        response.OutputStream.Write(buffer, 0, 32);
                        break;

                    case "login":
                        byte[] challenge = session["challenge"] as byte[];
                        if (challenge == null)
                            throw new WebDatabaseException("Challenge not initialized.");

                        session["challenge"] = null;

                        string authCode = request.QueryString["code"];
                        if (authCode == null)
                            throw new WebDatabaseException("Authentication code missing.");

                        using (HMAC hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sharedSecret)))
                        {
                            string computedAuthCode = BitConverter.ToString(hmac.ComputeHash(challenge)).Replace("-", "").ToLower();
                            if (authCode != computedAuthCode)
                                throw new WebDatabaseException("Invalid authentication code.");
                        }

                        session["token"] = request.ServerVariables["REMOTE_ADDR"];
                        response.OutputStream.Write(new byte[4], 0, 4);
                        break;

                    case "logout":
                        session.Abandon();
                        response.OutputStream.Write(new byte[4], 0, 4);
                        break;

                    default:
                        using (SqlDatabase DB = new SqlDatabase(conn))
                        {
                            WebDatabase.ExecuteQuery(DB, request, response, session);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                BinaryWriter bW = new BinaryWriter(response.OutputStream);

                //sql error code
                SqlException sqlEx = ex as SqlException;

                if (sqlEx == null)
                    bW.Write(-2);
                else
                    bW.Write(sqlEx.ErrorCode);

                //error message
                string errorMessage = ex.Message;
                bW.Write(errorMessage.Length);
                bW.Write(System.Text.Encoding.UTF8.GetBytes(errorMessage));

                //stack trace message
                string remoteStackTrace = ex.ToString();
                bW.Write(remoteStackTrace.Length);
                bW.Write(Encoding.UTF8.GetBytes(remoteStackTrace));

                bW.Flush();
            }
        }

        private static void ExecuteQuery(SqlDatabase DB, HttpRequest request, HttpResponse response, HttpSessionState session)
        {
            #region check token

            if ((string)session["token"] != request.ServerVariables["REMOTE_ADDR"])
                throw new WebDatabaseException("Access denied.");

            #endregion

            #region prepare sql command

            SqlCommand cmd = new SqlCommand(request.Form["q"]);

            foreach (string key in request.Form.AllKeys)
            {
                if (key != "q")
                {
                    using (MemoryStream mS = new MemoryStream(Convert.FromBase64String(request.Form[key])))
                    {
                        WebDbDataItem parameter = new WebDbDataItem(mS);

                        if (parameter.Value == null)
                            cmd.Parameters.Add(key, parameter.Type).Value = DBNull.Value;
                        else
                            cmd.Parameters.Add(key, parameter.Type).Value = parameter.Value;
                    }
                }
            }

            #endregion

            #region execute command

            if (cmd.CommandText.StartsWith("SELECT", StringComparison.OrdinalIgnoreCase))
            {
                #region TableQuery

                DataTable DT = DB.TableQuery(cmd);

                //write output
                BinaryWriter bW = new BinaryWriter(response.OutputStream);

                //error code
                bW.Write(0);

                //write column names
                bW.Write(Convert.ToByte(DT.Columns.Count));

                foreach (DataColumn col in DT.Columns)
                {
                    bW.Write(Convert.ToByte(col.ColumnName.Length));
                    bW.Write(Encoding.UTF8.GetBytes(col.ColumnName));
                }

                //write row data
                bW.Write(DT.Rows.Count);

                foreach (DataRow DR in DT.Rows)
                {
                    for (int iCol = 0; iCol < DT.Columns.Count; iCol++)
                    {
                        object value;

                        if (DR.IsNull(iCol))
                            value = null;
                        else
                            value = DR[iCol];

                        Type type = DR[iCol].GetType();
                        WebDbDataItem dbItem;

                        if (type == typeof(Int64))
                            dbItem = new WebDbDataItem(SqlDbType.BigInt, value);

                        else if (type == typeof(byte[]))
                            dbItem = new WebDbDataItem(SqlDbType.VarBinary, value);

                        else if (type == typeof(string))
                            dbItem = new WebDbDataItem(SqlDbType.NVarChar, value);

                        else if (type == typeof(DateTime))
                            dbItem = new WebDbDataItem(SqlDbType.DateTime, value);

                        else if (type == typeof(double))
                            dbItem = new WebDbDataItem(SqlDbType.Float, value);

                        else if (type == typeof(int))
                            dbItem = new WebDbDataItem(SqlDbType.Int, value);

                        else if (type == typeof(float))
                            dbItem = new WebDbDataItem(SqlDbType.Real, value);

                        else if (type == typeof(Int16))
                            dbItem = new WebDbDataItem(SqlDbType.SmallInt, value);

                        else if (type == typeof(byte))
                            dbItem = new WebDbDataItem(SqlDbType.TinyInt, value);

                        else if (type == typeof(DBNull))
                            dbItem = new WebDbDataItem(SqlDbType.TinyInt, null);

                        else
                            throw new Exception("Data type '" + type.ToString() + "' not supported.");

                        dbItem.WriteTo(bW);
                    }
                }

                bW.Flush();

                #endregion
            }
            else
            {
                #region Command

                int rowsAffected = DB.Command(cmd);

                //write output
                BinaryWriter bW = new BinaryWriter(response.OutputStream);
                bW.Write(0); //error code
                bW.Write(rowsAffected);
                bW.Flush();

                #endregion
            }

            #endregion
        }
    }
}
