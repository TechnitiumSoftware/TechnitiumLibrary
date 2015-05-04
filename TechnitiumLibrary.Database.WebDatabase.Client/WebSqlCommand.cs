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


namespace TechnitiumLibrary.Database.WebDatabase.Client
{
    public class WebSqlCommand
    {
        #region variables

        string _sqlQuery;
        ParameterDataCollection _parameters = new ParameterDataCollection();

        #endregion

        #region constructor

        public WebSqlCommand() { }

        public WebSqlCommand(string sqlQuery)
        {
            if (sqlQuery.EndsWith(";"))
                _sqlQuery = sqlQuery.Trim();
            else
                _sqlQuery = sqlQuery.Trim() + ";";
        }

        #endregion

        #region properties

        public ParameterDataCollection Parameters
        { get { return _parameters; } }

        public string SqlQuery
        {
            get { return _sqlQuery; }
            set
            {
                _sqlQuery = value.Trim();

                if (!_sqlQuery.EndsWith(";"))
                    _sqlQuery += ";";
            }
        }

        #endregion
    }
}