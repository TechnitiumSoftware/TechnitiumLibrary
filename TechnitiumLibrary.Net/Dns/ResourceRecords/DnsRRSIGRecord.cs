/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsRRSIGRecord : DnsResourceRecordData
    {
        #region variables

        DnsResourceRecordType _typeCovered;
        DnssecAlgorithm _algorithm;
        byte _labels;
        uint _originalTtl;
        uint _signatureExpiration;
        uint _signatureInception;
        ushort _keyTag;
        string _signersName;
        byte[] _signature;

        byte[] _serializedData;

        #endregion

        #region constructors

        public DnsRRSIGRecord(DnsResourceRecordType typeCovered, DnssecAlgorithm algorithm, byte labels, uint originalTtl, uint signatureExpiration, uint signatureInception, ushort keyTag, string signersName, byte[] signature)
        {
            _typeCovered = typeCovered;
            _algorithm = algorithm;
            _labels = labels;
            _originalTtl = originalTtl;
            _signatureExpiration = signatureExpiration;
            _signatureInception = signatureInception;
            _keyTag = keyTag;
            _signersName = signersName;
            _signature = signature;
        }

        public DnsRRSIGRecord(Stream s)
            : base(s)
        { }

        public DnsRRSIGRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _typeCovered = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _algorithm = (DnssecAlgorithm)s.ReadByteValue();
            _labels = s.ReadByteValue();
            _originalTtl = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureExpiration = DnsDatagram.ReadUInt32NetworkOrder(s);
            _signatureInception = DnsDatagram.ReadUInt32NetworkOrder(s);
            _keyTag = DnsDatagram.ReadUInt16NetworkOrder(s);
            _signersName = DnsDatagram.DeserializeDomainName(s);
            _signature = s.ReadBytes(_rdLength - 2 - 1 - 1 - 4 - 4 - 4 - 2 - DnsDatagram.GetSerializeDomainNameLength(_signersName));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            if (_serializedData is null)
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    DnsDatagram.WriteUInt16NetworkOrder((ushort)_typeCovered, mS);
                    mS.WriteByte((byte)_algorithm);
                    mS.WriteByte(_labels);
                    DnsDatagram.WriteUInt32NetworkOrder(_originalTtl, mS);
                    DnsDatagram.WriteUInt32NetworkOrder(_signatureExpiration, mS);
                    DnsDatagram.WriteUInt32NetworkOrder(_signatureInception, mS);
                    DnsDatagram.WriteUInt16NetworkOrder(_keyTag, mS);
                    DnsDatagram.SerializeDomainName(_signersName, mS);
                    mS.Write(_signature);

                    _serializedData = mS.ToArray();
                }
            }

            s.Write(_serializedData);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsRRSIGRecord other)
            {
                if (_typeCovered != other._typeCovered)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (_labels != other._labels)
                    return false;

                if (_originalTtl != other._originalTtl)
                    return false;

                if (_signatureExpiration != other._signatureExpiration)
                    return false;

                if (_signatureInception != other._signatureInception)
                    return false;

                if (_keyTag != other._keyTag)
                    return false;

                if (!_signersName.Equals(other._signersName))
                    return false;

                if (!BinaryNumber.Equals(_signature, other._signature))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();

            hash.Add(_typeCovered);
            hash.Add(_algorithm);
            hash.Add(_labels);
            hash.Add(_originalTtl);
            hash.Add(_signatureExpiration);
            hash.Add(_signatureInception);
            hash.Add(_keyTag);
            hash.Add(_signersName);
            hash.Add(_signature);

            return hash.ToHashCode();
        }

        public override string ToString()
        {
            return (ushort)_typeCovered + " " + (byte)_algorithm + " " + _labels + " " + _originalTtl + " " + _signatureExpiration + " ( " + _signatureInception + " " + _keyTag + " " + _signersName + " " + Convert.ToBase64String(_signature) + " )";
        }

        #endregion

        #region properties

        public DnsResourceRecordType TypeCovered
        { get { return _typeCovered; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public byte Labels
        { get { return _labels; } }

        public uint OriginalTtl
        { get { return _originalTtl; } }

        [IgnoreDataMember]
        public uint SignatureExpirationValue
        { get { return _signatureExpiration; } }

        public DateTime SignatureExpiration
        { get { return DateTime.UnixEpoch.AddSeconds(_signatureExpiration); } }

        [IgnoreDataMember]
        public uint SignatureInceptionValue
        { get { return _signatureInception; } }

        public DateTime SignatureInception
        { get { return DateTime.UnixEpoch.AddSeconds(_signatureInception); } }

        public ushort KeyTag
        { get { return _keyTag; } }

        public string SignersName
        { get { return _signersName; } }

        public byte[] Signature
        { get { return _signature; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 1 + 1 + 4 + 4 + 4 + 2 + DnsDatagram.GetSerializeDomainNameLength(_signersName) + _signature.Length); } }

        #endregion
    }
}
