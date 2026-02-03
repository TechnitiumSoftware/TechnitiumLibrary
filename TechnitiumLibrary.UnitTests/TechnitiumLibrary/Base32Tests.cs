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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public class Base32Tests
    {
        // RFC vectors for Base32
        private static readonly (string clear, string enc)[] RfcVectors =
        {
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======")
        };

        // Values that must decode and encode back identically
        private static readonly string[] RoundTripValues =
        {
            "", "10", "test130", "test", "8", "0", "=", "foobar"
        };

        // Arbitrary real-world binary sample from PHP tests
        private static readonly byte[] RandomBytes =
            Convert.FromBase64String("HgxBl1kJ4souh+ELRIHm/x8yTc/cgjDmiCNyJR/NJfs=");


        // -------------------- RFC vectors --------------------

        [TestMethod]
        public void ToBase32String_RfcVectors_ProduceExpectedOutput()
        {
            foreach ((string clear, string encoded) in RfcVectors)
            {
                // Arrange
                byte[] data = Encoding.ASCII.GetBytes(clear);

                // Act
                string result = Base32.ToBase32String(data);

                // Assert
                Assert.AreEqual(encoded, result, "Base32 encoding must match RFC vectors.");
            }
        }

        [TestMethod]
        public void FromBase32String_RfcVectors_DecodeCorrectly()
        {
            foreach ((string clear, string encoded) in RfcVectors)
            {
                // Arrange
                byte[] expected = Encoding.ASCII.GetBytes(clear);

                // Act
                byte[] result = Base32.FromBase32String(encoded);

                // Assert
                CollectionAssert.AreEqual(expected, result, "Decoding must invert RFC vectors.");
            }
        }


        // -------------------- RandomBytes encoding/decoding --------------------

        [TestMethod]
        public void ToBase32String_RandomBytes_MatchesExpectedEncoding()
        {
            // Given test fixture from PHP
            const string expected = "DYGEDF2ZBHRMULUH4EFUJAPG74PTETOP3SBDBZUIENZCKH6NEX5Q====";

            // Act
            string actual = Base32.ToBase32String(RandomBytes);

            Assert.AreEqual(expected, actual, "Binary encoding must be stable and deterministic.");
        }

        [TestMethod]
        public void FromBase32String_RandomBytes_ReturnsOriginalInput()
        {
            // Arrange
            const string encoded = "DYGEDF2ZBHRMULUH4EFUJAPG74PTETOP3SBDBZUIENZCKH6NEX5Q====";

            // Act
            byte[] decoded = Base32.FromBase32String(encoded);

            // Assert
            CollectionAssert.AreEqual(RandomBytes, decoded);
        }


        // -------------------- General encode/decode identity tests --------------------

        [TestMethod]
        public void EncodeDecode_RoundTrip_GivenKnownClearInputs_ReturnsOriginalValues()
        {
            foreach (string clear in RoundTripValues)
            {
                // Arrange
                byte[] bytes = Encoding.UTF8.GetBytes(clear);

                // Act
                string encoded = Base32.ToBase32String(bytes);
                byte[] decoded = Base32.FromBase32String(encoded);

                // Assert
                string decodedText = Encoding.UTF8.GetString(decoded);
                Assert.AreEqual(clear, decodedText, "Encode + decode must round-trip.");
            }
        }


        // -------------------- Explicit edge case tests --------------------

        [TestMethod]
        public void FromBase32String_GivenEmptyString_ReturnsEmptyArray()
        {
            byte[] result = Base32.FromBase32String("");
            Assert.IsEmpty(result);
        }

        [TestMethod]
        public void ToBase32String_GivenEmptyBytes_ReturnsEmptyString()
        {
            string result = Base32.ToBase32String(Array.Empty<byte>());
            Assert.IsEmpty(result);
        }

        [TestMethod]
        public void FromBase32String_GivenNullString_ThrowsException()
        {
            Assert.ThrowsExactly<NullReferenceException>(() => Base32.FromBase32String(null));

        }

        [TestMethod]
        public void FromBase32HexString_GivenNullString_ThrowsException()
        {
            Assert.ThrowsExactly<NullReferenceException>(() => Base32.FromBase32HexString(null));

        }

        [TestMethod]
        public void FromBase32String_GivenStringWithSpace_ThrowsException()
        {
            Assert.ThrowsExactly<IndexOutOfRangeException>(() => Base32.FromBase32String("MZXW6YTBOI====== "));

        }

        [TestMethod]
        public void FromBase32HexString_GivenStringWithSpace_ThrowsException()
        {
            Assert.ThrowsExactly<IndexOutOfRangeException>(() => Base32.FromBase32HexString("MZXW6YTBOI====== "));
        }
    }

    [TestClass]
    public class Base32HexTests
    {
        private static readonly (string clear, string enc)[] RfcVectors =
        {
            ("f",      "CO======"),
            ("fo",     "CPNG===="),
            ("foo",    "CPNMU==="),
            ("foob",   "CPNMUOG="),
            ("fooba",  "CPNMUOJ1"),
            ("foobar", "CPNMUOJ1E8======"),
        };

        private static readonly string[] RoundTripValues =
        {
            "", "10", "test130", "test", "8", "0", "=", "foobar"
        };

        private static readonly byte[] RandomBytes =
            Convert.FromBase64String("HgxBl1kJ4souh+ELRIHm/x8yTc/cgjDmiCNyJR/NJfs=");


        // ---------------- RFC vectors ----------------

        [TestMethod]
        public void ToBase32HexString_RfcVectors_ProduceExpectedOutput()
        {
            foreach ((string clear, string encoded) in RfcVectors)
            {
                byte[] data = Encoding.ASCII.GetBytes(clear);
                string result = Base32.ToBase32HexString(data);
                Assert.AreEqual(encoded, result, "Hex encoding must match RFC vectors.");
            }
        }

        [TestMethod]
        public void FromBase32HexString_RfcVectors_DecodeCorrectly()
        {
            foreach ((string clear, string encoded) in RfcVectors)
            {
                byte[] expected = Encoding.ASCII.GetBytes(clear);
                byte[] result = Base32.FromBase32HexString(encoded);
                CollectionAssert.AreEqual(expected, result);
            }
        }


        // ---------------- Known binary test ----------------

        [TestMethod]
        public void ToBase32HexString_RandomBytes_MatchesExpectedEncoding()
        {
            const string expected = "3O6435QP17HCKBK7S45K90F6VSFJ4JEFRI131PK84DP2A7UD4NTG====";
            string result = Base32.ToBase32HexString(RandomBytes);
            Assert.AreEqual(expected, result);
        }

        [TestMethod]
        public void FromBase32HexString_RandomBytes_ReturnsOriginalInput()
        {
            const string encoded = "3O6435QP17HCKBK7S45K90F6VSFJ4JEFRI131PK84DP2A7UD4NTG====";
            byte[] decoded = Base32.FromBase32HexString(encoded);
            CollectionAssert.AreEqual(RandomBytes, decoded);
        }


        // ---------------- Roundtrip tests ----------------

        [TestMethod]
        public void EncodeDecode_RoundTrip_GivenKnownClearInputs_ReturnsOriginal()
        {
            foreach (string clear in RoundTripValues)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(clear);
                string encoded = Base32.ToBase32HexString(bytes);
                byte[] decodedBytes = Base32.FromBase32HexString(encoded);
                string decoded = Encoding.UTF8.GetString(decodedBytes);

                Assert.AreEqual(clear, decoded);
            }
        }


        // ---------------- Explicit empty edge cases ----------------

        [TestMethod]
        public void FromBase32HexString_GivenEmpty_ReturnsEmptyArray()
        {
            byte[] result = Base32.FromBase32HexString("");
            Assert.IsEmpty(result);
        }

        [TestMethod]
        public void ToBase32HexString_GivenEmptyBytes_ReturnsEmptyString()
        {
            string result = Base32.ToBase32HexString(Array.Empty<byte>());
            Assert.IsEmpty(result);
        }
    }
}
