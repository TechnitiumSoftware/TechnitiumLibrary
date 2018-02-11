/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{

    /* Distinguished Encoding Rules
     * 
     * ASN.1 Type System
     * bits 7, 6 = CLASS
     * bit 5 = FORM
     * 
     * bit7 bit6    CLASS
     * 0    0       UNIVERSAL
     * 0    1       APPLICATION
     * 1    0       context-defined
     * 1    1       PRIVATE
     * 
     * bit5     FORM
     * 0        primitive
     * 1        constructed
     * 
     * reference: https://msdn.microsoft.com/en-us/library/windows/desktop/dd408078(v=vs.85).aspx
     */

    public enum DEREncodingASN1Type : byte
    {
        BIT_STRING = 0x03, //UNIVERSAL; Primitive
        BOOLEAN = 0x01, //UNIVERSAL; Primitive
        INTEGER = 0x02, //UNIVERSAL; Primitive
        NULL = 0x05, //UNIVERSAL; Primitive
        OBJECT_IDENTIFIER = 0x06, //UNIVERSAL; Primitive
        OCTET_STRING = 0x04, //UNIVERSAL; Primitive
        UNICODE_STRING = 0x1E,  //BMPString; UNIVERSAL; Primitive
        IA5_STRING = 0x16, //UNIVERSAL; Primitive
        PRINTABLE_STRING = 0x13, //UNIVERSAL; Primitive
        TeletexString = 0x14, //UNIVERSAL; Primitive
        UTF8_STRING = 0x0C, //UNIVERSAL; Primitive
        SEQUENCE = 0x30, //UNIVERSAL; constructed
        SET = 0x31 //UNIVERSAL; constructed
    }

    public class DEREncoding
    {
        #region variables

        DEREncodingASN1Type _type;
        byte[] _value;

        #endregion

        #region constructor

        private DEREncoding(DEREncodingASN1Type type, byte[] value)
        {
            _type = type;
            _value = value;
        }

        #endregion

        #region static

        public static DEREncoding Decode(byte[] data)
        {
            using (MemoryStream mS = new MemoryStream(data))
            {
                return Decode(mS);
            }
        }

        public static DEREncoding Decode(Stream s)
        {
            DEREncodingASN1Type type = (DEREncodingASN1Type)s.ReadByte();

            int valueLength;
            int length1 = s.ReadByte();

            if (length1 > 127)
            {
                int numberLenBytes = length1 & 0x7F;

                byte[] valueBytes = new byte[4];
                s.Read(valueBytes, 0, numberLenBytes);

                switch (numberLenBytes)
                {
                    case 1:
                        valueLength = valueBytes[0];
                        break;

                    case 2:
                        Array.Reverse(valueBytes, 0, 2);
                        valueLength = BitConverter.ToInt16(valueBytes, 0);
                        break;

                    case 3:
                        Array.Reverse(valueBytes, 0, 3);
                        valueLength = BitConverter.ToInt32(valueBytes, 0);
                        break;

                    case 4:
                        Array.Reverse(valueBytes, 0, 4);
                        valueLength = BitConverter.ToInt32(valueBytes, 0);
                        break;

                    default:
                        throw new IOException("DER encoding length not supported.");
                }
            }
            else
            {
                valueLength = length1;
            }

            byte[] value = new byte[valueLength];
            s.Read(value, 0, valueLength);

            return new DEREncoding(type, value);
        }

        public static void Encode(DEREncodingASN1Type type, byte[] value, Stream s)
        {
            s.WriteByte((byte)type);

            int valueLength = value.Length;

            if (valueLength < 128)
            {
                s.WriteByte((byte)valueLength);
            }
            else
            {
                byte[] bytesValueLength = BitConverter.GetBytes(valueLength);
                Array.Reverse(bytesValueLength);

                for (int i = 0; i < bytesValueLength.Length; i++)
                {
                    if (bytesValueLength[i] != 0)
                    {
                        s.WriteByte((byte)(0x80 | (bytesValueLength.Length - i)));
                        s.Write(bytesValueLength, i, bytesValueLength.Length - i);
                        break;
                    }
                }
            }

            s.Write(value, 0, valueLength);
        }

        public static void EncodeIntegerValue(byte[] value, Stream s)
        {
            if ((value[0] & 0x80) > 0)
            {
                byte[] valInt = new byte[value.Length + 1];
                Buffer.BlockCopy(value, 0, valInt, 1, value.Length);

                Encode(DEREncodingASN1Type.INTEGER, valInt, s);
            }
            else
            {
                Encode(DEREncodingASN1Type.INTEGER, value, s);
            }
        }

        public static RSAParameters DecodeRSAPrivateKey(byte[] data)
        {
            using (MemoryStream mS = new MemoryStream(data))
            {
                return DecodeRSAPrivateKey(mS);
            }
        }

        public static RSAParameters DecodeRSAPrivateKey(Stream s)
        {
            DEREncoding seq = Decode(s);

            using (Stream seqStream = seq.GetValueStream())
            {
                DEREncoding objVer = Decode(seqStream);

                if (objVer.Value[0] != 0)
                    throw new IOException("Unknown version number for RSA private key data.");

                DEREncoding objModulus = Decode(seqStream);
                DEREncoding objExponent = Decode(seqStream);
                DEREncoding objD = Decode(seqStream);
                DEREncoding objP = Decode(seqStream);
                DEREncoding objQ = Decode(seqStream);
                DEREncoding objDP = Decode(seqStream);
                DEREncoding objDQ = Decode(seqStream);
                DEREncoding objInverseQ = Decode(seqStream);

                RSAParameters parameters = new RSAParameters();

                parameters.Modulus = objModulus.GetIntegerValue();
                parameters.Exponent = objExponent.GetIntegerValue();
                parameters.D = objD.GetIntegerValue();
                parameters.P = objP.GetIntegerValue();
                parameters.Q = objQ.GetIntegerValue();
                parameters.DP = objDP.GetIntegerValue();
                parameters.DQ = objDQ.GetIntegerValue();
                parameters.InverseQ = objInverseQ.GetIntegerValue();

                return parameters;
            }
        }

        public static byte[] EncodeRSAPrivateKey(RSAParameters parameters)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                EncodeRSAPrivateKey(parameters, mS);

                return mS.ToArray();
            }
        }

        public static void EncodeRSAPrivateKey(RSAParameters parameters, Stream s)
        {
            using (MemoryStream seqStream = new MemoryStream())
            {
                Encode(DEREncodingASN1Type.INTEGER, new byte[] { 0 }, seqStream); //version

                EncodeIntegerValue(parameters.Modulus, seqStream);
                EncodeIntegerValue(parameters.Exponent, seqStream);
                EncodeIntegerValue(parameters.D, seqStream);
                EncodeIntegerValue(parameters.P, seqStream);
                EncodeIntegerValue(parameters.Q, seqStream);
                EncodeIntegerValue(parameters.DP, seqStream);
                EncodeIntegerValue(parameters.DQ, seqStream);
                EncodeIntegerValue(parameters.InverseQ, seqStream);

                //write sequence to output stream
                Encode(DEREncodingASN1Type.SEQUENCE, seqStream.ToArray(), s);
            }
        }

        public static RSAParameters DecodeRSAPublicKey(byte[] data)
        {
            using (MemoryStream mS = new MemoryStream(data))
            {
                return DecodeRSAPublicKey(mS);
            }
        }

        public static RSAParameters DecodeRSAPublicKey(Stream s)
        {
            DEREncoding seq = Decode(s);

            using (Stream seqStream = seq.GetValueStream())
            {
                DEREncoding objModulus = Decode(seqStream);
                DEREncoding objExponent = Decode(seqStream);

                RSAParameters parameters = new RSAParameters();

                parameters.Modulus = objModulus.GetIntegerValue();
                parameters.Exponent = objExponent.GetIntegerValue();

                return parameters;
            }
        }

        public static byte[] EncodeRSAPublicKey(RSAParameters parameters)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                EncodeRSAPublicKey(parameters, mS);

                return mS.ToArray();
            }
        }

        public static void EncodeRSAPublicKey(RSAParameters parameters, Stream s)
        {
            using (MemoryStream seqStream = new MemoryStream())
            {
                EncodeIntegerValue(parameters.Modulus, seqStream);
                EncodeIntegerValue(parameters.Exponent, seqStream);

                //write sequence to output stream
                Encode(DEREncodingASN1Type.SEQUENCE, seqStream.ToArray(), s);
            }
        }

        #endregion

        #region public

        public Stream GetValueStream()
        {
            return new MemoryStream(_value, false);
        }

        public void Encode(Stream s)
        {
            Encode(_type, _value, s);
        }

        public byte[] GetIntegerValue()
        {
            if (((_value.Length & 0x1) > 0) && (_value[0] == 0))
            {
                byte[] valInt = new byte[_value.Length - 1];
                Buffer.BlockCopy(_value, 1, valInt, 0, valInt.Length);
                return valInt;
            }
            else
            {
                return _value;
            }
        }

        #endregion

        #region properties

        public DEREncodingASN1Type Type
        { get { return _type; } }

        public byte[] Value
        { get { return _value; } }

        #endregion
    }
}
