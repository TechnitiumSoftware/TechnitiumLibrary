/*
Technitium Library
Copyright (C) 2016  Shreyas Zare (shreyas@technitium.com)

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
using System.Net.Mail;
using System.Text;

namespace TechnitiumLibrary.Security.Cryptography
{
    public enum CertificateProfileFlags : uint
    {
        None = 0x0,
        Name = 0x1,
        Type = 0x2,
        EmailAddress = 0x4,
        Website = 0x8,
        PhoneNumber = 0x10,
        StreetAddress = 0x20,
        City = 0x40,
        State = 0x80,
        Country = 0x100,
        PostalCode = 0x200,
        All = uint.MaxValue
    }

    public enum CertificateProfileType : byte
    {
        Unknown = 0,
        Individual = 1,
        Organization = 2
    }

    public sealed class CertificateProfile
    {
        #region variables

        byte _version;

        CertificateProfileFlags _flags = CertificateProfileFlags.None;
        CertificateProfileFlags _verified = CertificateProfileFlags.None;

        //optional fields below

        string _name = null;
        CertificateProfileType _type = CertificateProfileType.Unknown;

        MailAddress _emailAddress = null;
        Uri _website = null;
        string _phoneNumber = null;

        string _streetAddress = null;
        string _city = null;
        string _state = null;
        string _country = null;
        string _postalCode = null;

        #endregion

        #region constructor

        public CertificateProfile(string name = null, CertificateProfileType type = CertificateProfileType.Unknown, MailAddress emailAddress = null, Uri website = null, string phoneNumber = null, string streetAddress = null, string city = null, string state = null, string country = null, string postalCode = null, CertificateProfileFlags verificationFlags = CertificateProfileFlags.None)
        {
            _version = 1;
            _verified = verificationFlags;

            if (name != null)
            {
                _name = name;
                _flags |= CertificateProfileFlags.Name;
            }

            if (type != CertificateProfileType.Unknown)
            {
                _type = type;
                _flags |= CertificateProfileFlags.Type;
            }

            if (emailAddress != null)
            {
                _emailAddress = emailAddress;
                _flags |= CertificateProfileFlags.EmailAddress;
            }

            if (website != null)
            {
                _website = website;
                _flags |= CertificateProfileFlags.Website;
            }

            if (phoneNumber != null)
            {
                _phoneNumber = phoneNumber;
                _flags |= CertificateProfileFlags.PhoneNumber;
            }

            if (streetAddress != null)
            {
                _streetAddress = streetAddress;
                _flags |= CertificateProfileFlags.StreetAddress;
            }

            if (city != null)
            {
                _city = city;
                _flags |= CertificateProfileFlags.City;
            }

            if (state != null)
            {
                _state = state;
                _flags |= CertificateProfileFlags.State;
            }

            if (country != null)
            {
                _country = country;
                _flags |= CertificateProfileFlags.Country;
            }

            if (postalCode != null)
            {
                _postalCode = postalCode;
                _flags |= CertificateProfileFlags.PostalCode;
            }

            _verified = _verified & _flags;
        }

        public CertificateProfile(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "CP")
                throw new CryptoException("Invalid CertificateProfile format.");

            _version = bR.ReadByte();
            switch (_version)
            {
                case 1:
                    _flags = (CertificateProfileFlags)bR.ReadUInt32();
                    _verified = (CertificateProfileFlags)bR.ReadUInt32();

                    if ((_flags & CertificateProfileFlags.Name) > 0)
                        _name = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.Type) > 0)
                        _type = (CertificateProfileType)bR.ReadByte();

                    if ((_flags & CertificateProfileFlags.EmailAddress) > 0)
                        _emailAddress = new MailAddress(Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte())));

                    if ((_flags & CertificateProfileFlags.Website) > 0)
                        _website = new Uri(Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte())));

                    if ((_flags & CertificateProfileFlags.PhoneNumber) > 0)
                        _phoneNumber = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.StreetAddress) > 0)
                        _streetAddress = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.City) > 0)
                        _city = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.State) > 0)
                        _state = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.Country) > 0)
                        _country = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    if ((_flags & CertificateProfileFlags.PostalCode) > 0)
                        _postalCode = Encoding.UTF8.GetString(bR.ReadBytes(bR.ReadByte()));

                    break;

                default:
                    throw new CryptoException("CertificateProfile format version not supported.");
            }
        }

        #endregion

        #region public

        public bool FieldExists(CertificateProfileFlags field)
        {
            return (_flags & field) > 0;
        }

        public bool IsFieldVerified(CertificateProfileFlags field)
        {
            return (_verified & field) > 0;
        }

        public override string ToString()
        {
            StringBuilder output = new StringBuilder();

            if ((_flags & CertificateProfileFlags.Name) > 0)
            {
                if ((_verified & CertificateProfileFlags.Name) > 0)
                    output.AppendLine("Name (verified): " + _name);
                else
                    output.AppendLine("Name: " + _name);
            }

            if ((_flags & CertificateProfileFlags.EmailAddress) > 0)
            {
                if ((_verified & CertificateProfileFlags.EmailAddress) > 0)
                    output.AppendLine("Email Address (verified): " + _emailAddress.Address);
                else
                    output.AppendLine("Email Address: " + _emailAddress.Address);
            }

            if ((_flags & CertificateProfileFlags.Website) > 0)
            {
                if ((_verified & CertificateProfileFlags.Website) > 0)
                    output.AppendLine("Website (verified): " + _website.AbsoluteUri);
                else
                    output.AppendLine("Website: " + _website.AbsoluteUri);
            }

            if ((_flags & CertificateProfileFlags.PhoneNumber) > 0)
            {
                if ((_verified & CertificateProfileFlags.PhoneNumber) > 0)
                    output.AppendLine("Phone Number (verified): " + _phoneNumber);
                else
                    output.AppendLine("Phone Number: " + _phoneNumber);
            }

            if ((_flags & CertificateProfileFlags.StreetAddress) > 0)
            {
                if ((_verified & CertificateProfileFlags.StreetAddress) > 0)
                    output.AppendLine("Street Address (verified): " + _streetAddress);
                else
                    output.AppendLine("Street Address: " + _streetAddress);
            }

            if ((_flags & CertificateProfileFlags.City) > 0)
            {
                if ((_verified & CertificateProfileFlags.City) > 0)
                    output.AppendLine("City (verified): " + _city);
                else
                    output.AppendLine("City: " + _city);
            }

            if ((_flags & CertificateProfileFlags.State) > 0)
            {
                if ((_verified & CertificateProfileFlags.State) > 0)
                    output.AppendLine("State (verified): " + _state);
                else
                    output.AppendLine("State: " + _state);
            }

            if ((_flags & CertificateProfileFlags.Country) > 0)
            {
                if ((_verified & CertificateProfileFlags.Country) > 0)
                    output.AppendLine("Country (verified): " + _country);
                else
                    output.AppendLine("Country: " + _country);
            }

            if ((_flags & CertificateProfileFlags.PostalCode) > 0)
            {
                if ((_verified & CertificateProfileFlags.PostalCode) > 0)
                    output.AppendLine("PostalCode (verified): " + _postalCode);
                else
                    output.AppendLine("PostalCode: " + _postalCode);
            }

            return output.ToString();
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            CertificateProfile cP = obj as CertificateProfile;

            if (cP == null)
                return false;

            if (cP._version != _version)
                return false;

            if (cP._verified != _verified)
                return false;

            if (cP._name != _name)
                return false;

            if (cP._type != _type)
                return false;

            if ((cP._emailAddress != null) && (cP._emailAddress.Address != _emailAddress.Address))
                return false;

            if ((cP._website != null) && (cP._website.AbsoluteUri != _website.AbsoluteUri))
                return false;

            if (cP._phoneNumber != _phoneNumber)
                return false;

            if (cP._streetAddress != _streetAddress)
                return false;

            if (cP._city != _city)
                return false;

            if (cP._state != _state)
                return false;

            if (cP._country != _country)
                return false;

            if (cP._postalCode != _postalCode)
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public void WriteTo(Stream s)
        {
            byte[] buffer = null;

            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("CP"));
            bW.Write(_version);

            bW.Write((uint)_flags);
            bW.Write((uint)_verified);

            if ((_flags & CertificateProfileFlags.Name) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_name);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.Type) > 0)
                bW.Write((byte)_type);

            if ((_flags & CertificateProfileFlags.EmailAddress) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_emailAddress.Address);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.Website) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_website.AbsoluteUri);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.PhoneNumber) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_phoneNumber);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.StreetAddress) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_streetAddress);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.City) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_city);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.State) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_state);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.Country) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_country);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }

            if ((_flags & CertificateProfileFlags.PostalCode) > 0)
            {
                buffer = Encoding.UTF8.GetBytes(_postalCode);
                bW.Write(Convert.ToByte(buffer.Length));
                bW.Write(buffer);
            }
        }

        #endregion

        #region properties

        public byte Version
        { get { return _version; } }

        public CertificateProfileFlags Verified
        { get { return _verified; } }

        public CertificateProfileFlags Flags
        { get { return _flags; } }

        public string Name
        { get { return _name; } }

        public CertificateProfileType Type
        { get { return _type; } }

        public MailAddress EmailAddress
        { get { return _emailAddress; } }

        public Uri Website
        { get { return _website; } }

        public string PhoneNumber
        { get { return _phoneNumber; } }

        public string StreetAddress
        { get { return _streetAddress; } }

        public string City
        { get { return _city; } }

        public string State
        { get { return _state; } }

        public string Country
        { get { return _country; } }

        public string PostalCode
        { get { return _postalCode; } }

        #endregion
    }
}