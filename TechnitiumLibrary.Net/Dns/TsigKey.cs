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
using System.Security.Cryptography;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public enum TsigAlgorithm : byte
    {
        Unknown = 0,
        HMAC_MD5 = 1,
        GSS_TSIG = 2,
        HMAC_SHA1 = 3,
        HMAC_SHA224 = 4,
        HMAC_SHA256 = 5,
        HMAC_SHA256_128 = 6,
        HMAC_SHA384 = 7,
        HMAC_SHA384_192 = 8,
        HMAC_SHA512 = 9,
        HMAC_SHA512_256 = 10
    }

    public class TsigKey
    {
        #region variables

        readonly string _keyName;
        readonly string _sharedSecret;
        readonly TsigAlgorithm _algorithm;
        readonly string _algorithmName;

        #endregion

        #region constructor

        public TsigKey(string keyName, string sharedSecret, TsigAlgorithm algorithm)
        {
            _keyName = keyName;
            _sharedSecret = sharedSecret;
            _algorithm = algorithm;

            _algorithmName = GetTsigAlgorithmName(_algorithm);
        }

        public TsigKey(string keyName, string sharedSecret, string algorithmName)
        {
            _keyName = keyName;
            _sharedSecret = sharedSecret;
            _algorithmName = algorithmName;

            if (_algorithmName.Equals("hmac-md5", StringComparison.OrdinalIgnoreCase))
                _algorithmName = DnsTSIGRecordData.ALGORITHM_NAME_HMAC_MD5;

            _algorithm = GetTsigAlgorithm(_algorithmName);
        }

        public TsigKey(string keyName, string algorithmName)
        {
            _keyName = keyName;
            _algorithmName = algorithmName;

            if (_algorithmName.Equals("hmac-md5", StringComparison.OrdinalIgnoreCase))
                _algorithmName = DnsTSIGRecordData.ALGORITHM_NAME_HMAC_MD5;

            _algorithm = GetTsigAlgorithm(_algorithmName);

            byte[] key;

            switch (_algorithm)
            {
                case TsigAlgorithm.HMAC_SHA384:
                case TsigAlgorithm.HMAC_SHA384_192:
                    key = new byte[48];
                    break;

                case TsigAlgorithm.HMAC_SHA512:
                case TsigAlgorithm.HMAC_SHA512_256:
                    key = new byte[64];
                    break;

                default:
                    key = new byte[32];
                    break;
            }

            RandomNumberGenerator.Fill(key);

            _sharedSecret = Convert.ToBase64String(key);
        }

        #endregion

        #region private

        private static string GetTsigAlgorithmName(TsigAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case TsigAlgorithm.HMAC_MD5:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_MD5;

                case TsigAlgorithm.GSS_TSIG:
                    return DnsTSIGRecordData.ALGORITHM_NAME_GSS_TSIG;

                case TsigAlgorithm.HMAC_SHA1:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA1;

                case TsigAlgorithm.HMAC_SHA224:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA224;

                case TsigAlgorithm.HMAC_SHA256:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA256;

                case TsigAlgorithm.HMAC_SHA256_128:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA256_128;

                case TsigAlgorithm.HMAC_SHA384:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA384;

                case TsigAlgorithm.HMAC_SHA384_192:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA384_192;

                case TsigAlgorithm.HMAC_SHA512:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA512;

                case TsigAlgorithm.HMAC_SHA512_256:
                    return DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA512_256;

                default:
                    throw new NotSupportedException("TSIG algorithm is not supported.");
            }
        }

        private static TsigAlgorithm GetTsigAlgorithm(string algorithmName)
        {
            switch (algorithmName.ToLowerInvariant())
            {
                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_MD5:
                    return TsigAlgorithm.HMAC_MD5;

                case DnsTSIGRecordData.ALGORITHM_NAME_GSS_TSIG:
                    return TsigAlgorithm.GSS_TSIG;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA1:
                    return TsigAlgorithm.HMAC_SHA1;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA224:
                    return TsigAlgorithm.HMAC_SHA224;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA256:
                    return TsigAlgorithm.HMAC_SHA256;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA256_128:
                    return TsigAlgorithm.HMAC_SHA256_128;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA384:
                    return TsigAlgorithm.HMAC_SHA384;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA384_192:
                    return TsigAlgorithm.HMAC_SHA384_192;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA512:
                    return TsigAlgorithm.HMAC_SHA512;

                case DnsTSIGRecordData.ALGORITHM_NAME_HMAC_SHA512_256:
                    return TsigAlgorithm.HMAC_SHA512_256;

                default:
                    throw new NotSupportedException("TSIG algorithm is not supported.");
            }
        }

        #endregion

        #region properties

        public string KeyName
        { get { return _keyName; } }

        public string SharedSecret
        { get { return _sharedSecret; } }

        public TsigAlgorithm Algorithm
        { get { return _algorithm; } }

        public string AlgorithmName
        { get { return _algorithmName; } }

        #endregion
    }
}
