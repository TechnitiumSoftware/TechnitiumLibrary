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

using System.Collections.Generic;

namespace TechnitiumLibrary.Database.WebDatabase.Client
{
    public class WebDataRow
    {
        #region variables

        List<string> _columns;
        List<WebDbDataItem> _items = new List<WebDbDataItem>();

        #endregion

        #region constructor

        public WebDataRow(WebDataTable DT)
        {
            _columns = DT.Columns;
        }

        #endregion

        #region properties

        public List<WebDbDataItem> Items
        { get { return _items; } }

        public object this[int index]
        {
            get
            {
                if (_items[index] == null)
                    return null;
                else
                    return _items[index].Value;
            }
        }

        public object this[string column]
        {
            get
            {
                int index = _columns.IndexOf(column);
                if (index < 0)
                    throw new WebDatabaseException("Column name '" + column + "' was not found.");

                return _items[index].Value;
            }
        }

        #endregion
    }
}