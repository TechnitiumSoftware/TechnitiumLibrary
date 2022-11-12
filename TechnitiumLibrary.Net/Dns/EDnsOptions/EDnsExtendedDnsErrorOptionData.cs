/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.Serialization;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    //Extended DNS Errors
    //https://datatracker.ietf.org/doc/html/rfc8914

    public enum EDnsExtendedDnsErrorCode : ushort
    {
        /// <summary>
        /// The error in question falls into a category that does not match known extended error codes. Implementations SHOULD include an EXTRA-TEXT value to augment this error code with additional information.
        /// </summary>
        Other = 0,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but a DNSKEY RRset contained only unsupported DNSSEC algorithms.
        /// </summary>
        UnsupportedDnsKeyAlgorithm = 1,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but a DS RRset contained only unsupported Digest Types.
        /// </summary>
        UnsupportedDsDigestType = 2,

        /// <summary>
        /// The resolver was unable to resolve the answer within its time limits and decided to answer with previously cached data instead of answering with an error. This is typically caused by problems communicating with an authoritative server, possibly as result of a denial of service (DoS) attack against another network. (See also Code 19.)
        /// </summary>
        StaleAnswer = 3,

        /// <summary>
        /// For policy reasons (legal obligation or malware filtering, for instance), an answer was forged. Note that this should be used when an answer is still provided, not when failure codes are returned instead. See Blocked (15), Censored (16), and Filtered (17) for use when returning other response codes.
        /// </summary>
        ForgedAnswer = 4,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but validation ended in the Indeterminate state [RFC4035]
        /// </summary>
        DnssecIndeterminate = 5,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but validation ended in the Bogus state.
        /// </summary>
        DnssecBogus = 6,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and some (often all) are expired.
        /// </summary>
        SignatureExpired = 7,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but no signatures are presently valid and at least some are not yet valid.
        /// </summary>
        SignatureNotYetValid = 8,

        /// <summary>
        /// A DS record existed at a parent, but no supported matching DNSKEY record could be found for the child.
        /// </summary>
        DNSKEYMissing = 9,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but no RRSIGs could be found for at least one RRset where RRSIGs were expected.
        /// </summary>
        RRSIGsMissing = 10,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but no Zone Key Bit was set in a DNSKEY.
        /// </summary>
        NoZoneKeyBitSet = 11,

        /// <summary>
        /// The resolver attempted to perform DNSSEC validation, but the requested data was missing and a covering NSEC or NSEC3 was not provided.
        /// </summary>
        NSECMissing = 12,

        /// <summary>
        /// The resolver is returning the SERVFAIL RCODE from its cache.
        /// </summary>
        CachedError = 13,

        /// <summary>
        /// The server is unable to answer the query, as it was not fully functional when the query was received.
        /// </summary>
        NotReady = 14,

        /// <summary>
        /// The server is unable to respond to the request because the domain is on a blocklist due to an internal security policy imposed by the operator of the server resolving or forwarding the query.
        /// </summary>
        Blocked = 15,

        /// <summary>
        /// The server is unable to respond to the request because the domain is on a blocklist due to an external requirement imposed by an entity other than the operator of the server resolving or forwarding the query. Note that how the imposed policy is applied is irrelevant (in-band DNS filtering, court order, etc.).
        /// </summary>
        Censored = 16,

        /// <summary>
        /// The server is unable to respond to the request because the domain is on a blocklist as requested by the client. Functionally, this amounts to "you requested that we filter domains like this one."
        /// </summary>
        Filtered = 17,

        /// <summary>
        /// An authoritative server or recursive resolver that receives a query from an "unauthorized" client can annotate its REFUSED message with this code. Examples of "unauthorized" clients are recursive queries from IP addresses outside the network, blocklisted IP addresses, local policy, etc.
        /// </summary>
        Prohibited = 18,

        /// <summary>
        /// The resolver was unable to resolve an answer within its configured time limits and decided to answer with a previously cached NXDOMAIN answer instead of answering with an error. This may be caused, for example, by problems communicating with an authoritative server, possibly as result of a denial of service (DoS) attack against another network. (See also Code 3.)
        /// </summary>
        StaleNxDomainAnswer = 19,

        /// <summary>
        /// An authoritative server that receives a query with the Recursion Desired (RD) bit clear, or when it is not configured for recursion for a domain for which it is not authoritative, SHOULD include this EDE code in the REFUSED response. A resolver that receives a query with the RD bit clear SHOULD include this EDE code in the REFUSED response.
        /// </summary>
        NotAuthoritative = 20,

        /// <summary>
        /// The requested operation or query is not supported.
        /// </summary>
        NotSupported = 21,

        /// <summary>
        /// The resolver could not reach any of the authoritative name servers (or they potentially refused to reply).
        /// </summary>
        NoReachableAuthority = 22,

        /// <summary>
        /// An unrecoverable error occurred while communicating with another server.
        /// </summary>
        NetworkError = 23,

        /// <summary>
        /// The authoritative server cannot answer with data for a zone it is otherwise configured to support. Examples of this include its most recent zone being too old or having expired.
        /// </summary>
        InvalidData = 24
    }

    public class EDnsExtendedDnsErrorOptionData : EDnsOptionData
    {
        #region variables

        EDnsExtendedDnsErrorCode _infoCode;
        string _extraText;

        #endregion

        #region constructor

        public EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode infoCode, string extraText)
        {
            _infoCode = infoCode;
            _extraText = extraText;
        }

        public EDnsExtendedDnsErrorOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            _infoCode = (EDnsExtendedDnsErrorCode)DnsDatagram.ReadUInt16NetworkOrder(s);

            int textLength = _length - 2;
            if (textLength > 0)
                _extraText = Encoding.UTF8.GetString(s.ReadBytes(textLength));
        }

        protected override void WriteOptionData(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_infoCode, s);

            if (!string.IsNullOrEmpty(_extraText))
                s.Write(Encoding.UTF8.GetBytes(_extraText));
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsExtendedDnsErrorOptionData other)
            {
                if (_infoCode != other._infoCode)
                    return false;

                if (!string.Equals(_extraText, other._extraText))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_infoCode, _extraText);
        }

        public override string ToString()
        {
            return "[" + _infoCode.ToString() + (_extraText is null ? "" : ": " + _extraText) + "]";
        }

        #endregion

        #region properties

        public EDnsExtendedDnsErrorCode InfoCode
        { get { return _infoCode; } }

        public string ExtraText
        { get { return _extraText; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + (_extraText is null ? 0 : _extraText.Length)); } }

        #endregion
    }
}
