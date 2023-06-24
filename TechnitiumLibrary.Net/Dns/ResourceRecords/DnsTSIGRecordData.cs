/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnsTsigError : ushort
    {
        NoError = 0,
        BADSIG = 16,
        BADKEY = 17,
        BADTIME = 18,
        BADTRUNC = 22
    }

    //Secret Key Transaction Authentication for DNS (TSIG)
    //https://datatracker.ietf.org/doc/html/rfc8945

    public class DnsTSIGRecordData : DnsResourceRecordData
    {
        #region constants

        public const string ALGORITHM_NAME_HMAC_MD5 = "hmac-md5.sig-alg.reg.int";
        public const string ALGORITHM_NAME_GSS_TSIG = "gss-tsig";
        public const string ALGORITHM_NAME_HMAC_SHA1 = "hmac-sha1";
        public const string ALGORITHM_NAME_HMAC_SHA224 = "hmac-sha224";
        public const string ALGORITHM_NAME_HMAC_SHA256 = "hmac-sha256";
        public const string ALGORITHM_NAME_HMAC_SHA256_128 = "hmac-sha256-128";
        public const string ALGORITHM_NAME_HMAC_SHA384 = "hmac-sha384";
        public const string ALGORITHM_NAME_HMAC_SHA384_192 = "hmac-sha384-192";
        public const string ALGORITHM_NAME_HMAC_SHA512 = "hmac-sha512";
        public const string ALGORITHM_NAME_HMAC_SHA512_256 = "hmac-sha512-256";

        #endregion

        #region variables

        string _algorithmName;
        ulong _timeSigned;
        ushort _fudge;
        byte[] _mac;
        ushort _originalID;
        DnsTsigError _error;
        byte[] _otherData;

        #endregion

        #region constructor

        public DnsTSIGRecordData(string algorithmName, DateTime timeSigned, ushort fudge, byte[] mac, ushort originalID, DnsTsigError error, byte[] otherData)
            : this(algorithmName, Convert.ToUInt64((timeSigned - DateTime.UnixEpoch).TotalSeconds), fudge, mac, originalID, error, otherData)
        { }

        public DnsTSIGRecordData(string algorithmName, ulong timeSigned, ushort fudge, byte[] mac, ushort originalID, DnsTsigError error, byte[] otherData)
        {
            _algorithmName = algorithmName;
            _timeSigned = timeSigned;
            _fudge = fudge;
            _mac = mac;
            _originalID = originalID;
            _error = error;
            _otherData = otherData;
        }

        public DnsTSIGRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _algorithmName = DnsDatagram.DeserializeDomainName(s);
            _timeSigned = DnsDatagram.ReadUInt48NetworkOrder(s);
            _fudge = DnsDatagram.ReadUInt16NetworkOrder(s);

            ushort macSize = DnsDatagram.ReadUInt16NetworkOrder(s);
            _mac = s.ReadBytes(macSize);

            _originalID = DnsDatagram.ReadUInt16NetworkOrder(s);
            _error = (DnsTsigError)DnsDatagram.ReadUInt16NetworkOrder(s);

            ushort otherLen = DnsDatagram.ReadUInt16NetworkOrder(s);
            _otherData = s.ReadBytes(otherLen);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _algorithmName.ToLowerInvariant() : _algorithmName, s); //MUST NOT be compressed
            DnsDatagram.WriteUInt48NetworkOrder(_timeSigned, s);
            DnsDatagram.WriteUInt16NetworkOrder(_fudge, s);

            DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(_mac.Length), s);
            s.Write(_mac);

            DnsDatagram.WriteUInt16NetworkOrder(_originalID, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_error, s);

            DnsDatagram.WriteUInt16NetworkOrder(Convert.ToUInt16(_otherData.Length), s);
            s.Write(_otherData);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTSIGRecordData other)
            {
                if (!_algorithmName.Equals(other._algorithmName, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_timeSigned != other._timeSigned)
                    return false;

                if (_fudge != other._fudge)
                    return false;

                if (!BinaryNumber.Equals(_mac, other._mac))
                    return false;

                if (_originalID != other._originalID)
                    return false;

                if (_error != other._error)
                    return false;

                if (!BinaryNumber.Equals(_otherData, other._otherData))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_algorithmName, _timeSigned, _fudge, _mac, _originalID, _error, _otherData);
        }

        public override string ToString()
        {
            return _algorithmName + ". " + _timeSigned + " " + _fudge + " " + Convert.ToBase64String(_mac) + " " + _originalID + " " + _error + " " + Convert.ToBase64String(_otherData);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("AlgorithmName", _algorithmName);
            jsonWriter.WriteNumber("TimeSigned", _timeSigned);
            jsonWriter.WriteNumber("Fudge", _fudge);
            jsonWriter.WriteString("MAC", Convert.ToBase64String(_mac));
            jsonWriter.WriteNumber("OriginalID", _originalID);
            jsonWriter.WriteString("Error", _error.ToString());
            jsonWriter.WriteString("OtherData", Convert.ToBase64String(_otherData));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string AlgorithmName
        { get { return _algorithmName; } }

        public ulong TimeSigned
        { get { return _timeSigned; } }

        public ushort Fudge
        { get { return _fudge; } }

        public byte[] MAC
        { get { return _mac; } }

        public ushort OriginalID
        { get { return _originalID; } }

        public DnsTsigError Error
        { get { return _error; } }

        public byte[] OtherData
        { get { return _otherData; } }

        public override int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_algorithmName) + 6 + 2 + 2 + _mac.Length + 2 + 2 + 2 + _otherData.Length; } }

        #endregion
    }
}
