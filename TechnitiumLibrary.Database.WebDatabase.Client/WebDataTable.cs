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
    public class WebDataTable
    {
        #region variables

        List<string> _columns = new List<string>();
        List<WebDataRow> _rows = new List<WebDataRow>();

        #endregion

        #region properties

        public List<string> Columns
        { get { return _columns; } }

        public List<WebDataRow> Rows
        { get { return _rows; } }

        public WebDataRow this[int index]
        { get { return _rows[index]; } }

        #endregion
    }
}