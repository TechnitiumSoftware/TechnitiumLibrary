/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Text;
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    public class EDnsNsidOptionData : EDnsUnknownOptionData
    {
        #region variables

        readonly string _nameServerIdentifier;

        #endregion

        #region constructor

        public EDnsNsidOptionData()
            : base([])
        {
            _nameServerIdentifier = "";
        }

        public EDnsNsidOptionData(byte[] nameServerIdentifier)
            : base(nameServerIdentifier)
        {
            _nameServerIdentifier = GetPresentationFormat();
        }

        public EDnsNsidOptionData(string nameServerIdentifier)
        {
            _nameServerIdentifier = nameServerIdentifier;

            byte[] nsid;

            try
            {
                if (nameServerIdentifier.Contains(':'))
                    nsid = nameServerIdentifier.ParseColonHexString();
                else
                    nsid = Convert.FromHexString(nameServerIdentifier);
            }
            catch
            {
                nsid = Encoding.UTF8.GetBytes(nameServerIdentifier);
            }

            _data = nsid;
        }

        public EDnsNsidOptionData(Stream s)
            : base(s)
        {
            _nameServerIdentifier = GetPresentationFormat();
        }

        #endregion

        #region private

        private string GetPresentationFormat()
        {
            string nameServerIdentifier = Encoding.ASCII.GetString(_data);

            if (nameServerIdentifier.Contains('?'))
                nameServerIdentifier = Convert.ToHexStringLower(_data);

            return nameServerIdentifier;
        }

        #endregion

        #region public

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Data", _nameServerIdentifier);

            jsonWriter.WriteEndObject();
        }

        #endregion
    }
}
