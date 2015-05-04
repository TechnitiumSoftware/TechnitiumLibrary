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

using System.Collections.Specialized;
using System.Data;

namespace TechnitiumLibrary.Database.WebDatabase
{
    public class ParameterDataCollection : NameObjectCollectionBase
    {
        #region public

        public void Add(string parameter, WebDbDataItem value)
        {
            base.BaseAdd(parameter, value);
        }

        public void Add(string parameter, SqlDbType type, object value)
        {
            base.BaseAdd(parameter, new WebDbDataItem(type, value));
        }

        #endregion

        #region properties

        public WebDbDataItem this[int index]
        {
            get { return (WebDbDataItem)base.BaseGet(index); }
            set { base.BaseSet(index, value); }
        }

        public WebDbDataItem this[string name]
        {
            get { return (WebDbDataItem)base.BaseGet(name); }
            set { base.BaseSet(name, value); }
        }

        #endregion
    }
}