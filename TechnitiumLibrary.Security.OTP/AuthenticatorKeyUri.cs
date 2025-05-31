/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using QRCoder;
using System;
using System.Security.Cryptography;
using System.Web;

namespace TechnitiumLibrary.Security.OTP
{
    //https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    public class AuthenticatorKeyUri
    {
        #region variables

        readonly string _type;
        readonly string _issuer;
        readonly string _accountName;
        readonly string _secret;
        readonly string _algorithm = "SHA1";
        readonly int _digits = 6;
        readonly int _period = 30;

        #endregion

        #region constructor

        public AuthenticatorKeyUri(string type, string issuer, string accountName, string secret, string algorithm = "SHA1", int digits = 6, int period = 30)
        {
            ArgumentNullException.ThrowIfNull(type, nameof(type));
            ArgumentNullException.ThrowIfNull(issuer, nameof(issuer));
            ArgumentNullException.ThrowIfNull(accountName, nameof(accountName));
            ArgumentNullException.ThrowIfNull(secret, nameof(secret));

            if (algorithm is null)
                algorithm = "SHA1";

            if ((digits < 6) || (digits > 8))
                throw new ArgumentOutOfRangeException(nameof(digits), "The digits value must be in 6-8 range.");

            if (period < 0)
                throw new ArgumentOutOfRangeException(nameof(period), "The period value must be a positive integer.");

            _type = type;
            _issuer = issuer;
            _accountName = accountName;
            _secret = secret;
            _algorithm = algorithm;
            _digits = digits;
            _period = period;
        }

        #endregion

        #region static

        public static AuthenticatorKeyUri Generate(string issuer, string accountName, int keySize = 10, string algorithm = "SHA1", int digits = 6, int period = 30)
        {
            Span<byte> key = stackalloc byte[keySize];
            RandomNumberGenerator.Fill(key);

            string secret = Base32.ToBase32String(key, true);

            return new AuthenticatorKeyUri("totp", issuer, accountName, secret, algorithm, digits, period);
        }

        public static AuthenticatorKeyUri Parse(string keyUri)
        {
            return Parse(new Uri(keyUri));
        }

        public static AuthenticatorKeyUri Parse(Uri keyUri)
        {
            if (!keyUri.Scheme.Equals("otpauth", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"Failed to generate OTP: the key URI scheme '{keyUri.Scheme}' is not supported.");

            string type = HttpUtility.UrlDecode(keyUri.Host.ToLowerInvariant());
            string issuer = null;
            string accountName;
            string secret = null;
            string algorithm = "SHA1";
            int digits = 6;
            int period = 30;

            string[] pathParts = keyUri.AbsolutePath.Split('/');
            if (pathParts.Length != 2)
                throw new ArgumentException("Failed to generate OTP: the key URI format is invalid.");

            string label = HttpUtility.UrlDecode(pathParts[1]);
            string[] labelParts = label.Split(':', 2);
            if (labelParts.Length == 1)
            {
                accountName = labelParts[0];
            }
            else
            {
                issuer = labelParts[0];
                accountName = labelParts[1];
            }

            string[] queryParts = keyUri.Query.TrimStart('?').Split('&');

            foreach (string queryPart in queryParts)
            {
                string[] keyValue = queryPart.Split('=', 2);

                switch (keyValue[0].ToLowerInvariant())
                {
                    case "secret":
                        secret = HttpUtility.UrlDecode(keyValue[1]);
                        break;

                    case "issuer":
                        issuer = HttpUtility.UrlDecode(keyValue[1]);
                        break;

                    case "algorithm":
                        algorithm = HttpUtility.UrlDecode(keyValue[1]);
                        break;

                    case "digits":
                        if (!int.TryParse(keyValue[1], out digits))
                            throw new ArgumentException("Failed to generate OTP: the key URI 'digits' parameter failed to parse.");

                        break;

                    case "period":
                        if (!int.TryParse(keyValue[1], out period))
                            throw new ArgumentException("Failed to generate OTP: the key URI 'period' parameter failed to parse.");

                        break;
                }
            }

            return new AuthenticatorKeyUri(type, issuer, accountName, secret, algorithm, digits, period);
        }

        #endregion

        #region public

        public byte[] GetQRCodePngImage(int pixelsPerModule = 5)
        {
            using (QRCodeGenerator qrGenerator = new QRCodeGenerator())
            {
                using (QRCodeData qrCodeData = qrGenerator.CreateQrCode(ToString(), QRCodeGenerator.ECCLevel.Q))
                {
                    using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
                    {
                        return qrCode.GetGraphic(pixelsPerModule);
                    }
                }
            }
        }

        public override string ToString()
        {
            return "otpauth://" + HttpUtility.UrlEncode(_type) + "/" + HttpUtility.UrlEncode(_issuer) + ":" + HttpUtility.UrlEncode(_accountName) + "?" +
                "secret=" + HttpUtility.UrlEncode(_secret) +
                "&issuer=" + HttpUtility.UrlEncode(_issuer) +
                "&algorithm=" + HttpUtility.UrlEncode(_algorithm) +
                "&digits=" + _digits +
                "&period=" + _period;
        }

        #endregion

        #region properties

        public string Type
        { get { return _type; } }

        public string Issuer
        { get { return _issuer; } }

        public string AccountName
        { get { return _accountName; } }

        public string Secret
        { get { return _secret; } }

        public string Algorithm
        { get { return _algorithm; } }

        public int Digits
        { get { return _digits; } }

        public int Period
        { get { return _period; } }

        #endregion
    }
}
