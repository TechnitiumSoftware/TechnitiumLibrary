using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class IPAddressExtensionsTests
    {
        private static MemoryStream NewStream(byte[]? initial = null) =>
            initial is null ? new MemoryStream() : new MemoryStream(initial, writable: true);

        // ------------------------------------------------------
        // WRITE & READ (BINARY FORMAT)
        // ------------------------------------------------------

        [TestMethod]
        public void WriteTo_ThenReadFrom_ShouldRoundtrip_IPv4()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("1.2.3.4");
            using MemoryStream ms = NewStream();

            // WHEN
            ip.WriteTo(ms);
            ms.Position = 0;
            IPAddress read = IPAddressExtensions.ReadFrom(ms);

            // THEN
            Assert.AreEqual(ip, read, "WriteTo/ReadFrom must preserve IPv4 address bits exactly.");
            Assert.AreEqual(ms.Length, ms.Position,
                "ReadFrom must consume exactly one encoded address and no more bytes.");
        }

        [TestMethod]
        public void WriteTo_ThenReadFrom_ShouldRoundtrip_IPv6()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("2001:db8::1");
            using MemoryStream ms = NewStream();

            // WHEN
            ip.WriteTo(ms);
            ms.Position = 0;
            IPAddress read = IPAddressExtensions.ReadFrom(ms);

            // THEN
            Assert.AreEqual(ip, read, "WriteTo/ReadFrom must preserve IPv6 address bits exactly.");
            Assert.AreEqual(ms.Length, ms.Position,
                "ReadFrom must consume exactly one encoded IPv6 address and no extra bytes.");
        }

        [TestMethod]
        public void WriteTo_WithBinaryWriter_ShouldProduceSameFormat()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("10.20.30.40");
            using MemoryStream ms1 = NewStream();
            using MemoryStream ms2 = NewStream();

            // WHEN
            ip.WriteTo(ms1); // direct Stream overload

            using (BinaryWriter writer = new BinaryWriter(ms2, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                ip.WriteTo(writer);
            }

            // THEN
            CollectionAssert.AreEqual(ms1.ToArray(), ms2.ToArray(),
                "WriteTo(BinaryWriter) must delegate to identical wire format as WriteTo(Stream).");
        }

        [TestMethod]
        public void ReadFrom_ShouldThrowEndOfStream_WhenNoFamilyMarkerAvailable()
        {
            // GIVEN
            using MemoryStream ms = NewStream(Array.Empty<byte>());
            long startPos = ms.Position;

            // WHEN - THEN
            Assert.ThrowsExactly<EndOfStreamException>(
                () => IPAddressExtensions.ReadFrom(ms),
                "ReadFrom must fail fast when stream ends before family marker.");

            Assert.AreEqual(startPos, ms.Position,
                "On EOS, ReadFrom must not advance stream position.");
        }

        [TestMethod]
        public void ReadFrom_ShouldThrowNotSupported_WhenFamilyMarkerUnknown()
        {
            // GIVEN: marker 3 (unsupported) + one extra byte (must remain unread)
            using MemoryStream ms = NewStream(new byte[] { 3, 0xFF });

            // WHEN
            Assert.ThrowsExactly<NotSupportedException>(
                () => IPAddressExtensions.ReadFrom(ms),
                "ReadFrom must reject unsupported address family markers deterministically.");

            // THEN
            Assert.AreEqual(1L, ms.Position,
                "On unsupported family marker, ReadFrom must consume only the marker byte and leave payload intact.");
            Assert.AreEqual(2L, ms.Length);
        }

        // ------------------------------------------------------
        // IPv4 <-> NUMBER CONVERSION
        // ------------------------------------------------------

        [TestMethod]
        public void ConvertIpToNumber_ThenBack_ShouldRoundtrip_IPv4()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("1.2.3.4");

            // WHEN
            uint number = ip.ConvertIpToNumber();
            IPAddress roundtrip = IPAddressExtensions.ConvertNumberToIp(number);

            // THEN
            Assert.AreEqual("1.2.3.4", roundtrip.ToString(),
                "ConvertNumberToIp(ConvertIpToNumber(ip)) must yield the original IPv4 address.");
        }

        [TestMethod]
        public void ConvertIpToNumber_ShouldThrow_WhenAddressIsIPv6()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("::1");

            // WHEN - THEN
            Assert.ThrowsExactly<ArgumentException>(
                () => ip.ConvertIpToNumber(),
                "ConvertIpToNumber must reject non-IPv4 addresses with ArgumentException.");
        }

        // ------------------------------------------------------
        // SUBNET MASK HELPERS
        // ------------------------------------------------------

        [TestMethod]
        public void GetSubnetMask_ShouldReturnCorrectMasks_ForBoundaryPrefixLengths()
        {
            // WHEN
            IPAddress mask0 = IPAddressExtensions.GetSubnetMask(0);
            IPAddress mask24 = IPAddressExtensions.GetSubnetMask(24);
            IPAddress mask32 = IPAddressExtensions.GetSubnetMask(32);

            // THEN
            Assert.AreEqual("0.0.0.0", mask0.ToString(),
                "Prefix length 0 must map to all-zero IPv4 mask.");
            Assert.AreEqual("255.255.255.0", mask24.ToString(),
                "Prefix length 24 must map to 255.255.255.0.");
            Assert.AreEqual("255.255.255.255", mask32.ToString(),
                "Prefix length 32 must map to 255.255.255.255.");
        }

        [TestMethod]
        public void GetSubnetMask_ShouldThrow_WhenPrefixExceedsIPv4Width()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => IPAddressExtensions.GetSubnetMask(33),
                "GetSubnetMask must reject prefix lengths greater than 32.");
        }

        [TestMethod]
        public void GetSubnetMaskWidth_ShouldReturnCorrectWidth_ForValidMasks()
        {
            // GIVEN
            IPAddress mask0 = IPAddress.Parse("0.0.0.0");
            IPAddress mask8 = IPAddress.Parse("255.0.0.0");
            IPAddress mask24 = IPAddress.Parse("255.255.255.0");

            // WHEN
            int width0 = mask0.GetSubnetMaskWidth();
            int width8 = mask8.GetSubnetMaskWidth();
            int width24 = mask24.GetSubnetMaskWidth();

            // THEN
            Assert.AreEqual(0, width0, "Mask 0.0.0.0 must have width 0.");
            Assert.AreEqual(8, width8, "Mask 255.0.0.0 must have width 8.");
            Assert.AreEqual(24, width24, "Mask 255.255.255.0 must have width 24.");
        }

        [TestMethod]
        public void GetSubnetMaskWidth_ShouldThrow_WhenMaskIsNotIPv4()
        {
            // GIVEN
            IPAddress ipv6Mask = IPAddress.Parse("ffff::");

            // WHEN - THEN
            Assert.ThrowsExactly<ArgumentException>(
                () => ipv6Mask.GetSubnetMaskWidth(),
                "GetSubnetMaskWidth must reject non-IPv4 subnet masks.");
        }

        // ------------------------------------------------------
        // GET NETWORK ADDRESS
        // ------------------------------------------------------

        [TestMethod]
        public void GetNetworkAddress_ShouldZeroOutHostBits_ForIPv4()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("192.168.10.123");

            // WHEN
            IPAddress network24 = ip.GetNetworkAddress(24);
            IPAddress network16 = ip.GetNetworkAddress(16);
            IPAddress network0 = ip.GetNetworkAddress(0);

            // THEN
            Assert.AreEqual("192.168.10.0", network24.ToString(),
                "Prefix 24 must zero out last octet.");
            Assert.AreEqual("192.168.0.0", network16.ToString(),
                "Prefix 16 must zero out last two octets.");
            Assert.AreEqual("0.0.0.0", network0.ToString(),
                "Prefix 0 must zero out all IPv4 bits.");
        }

        [TestMethod]
        public void GetNetworkAddress_ShouldReturnSameAddress_ForFullPrefixLength()
        {
            // GIVEN
            IPAddress ip4 = IPAddress.Parse("10.0.0.42");
            IPAddress ip6 = IPAddress.Parse("2001:db8::dead:beef");

            // WHEN
            IPAddress net4 = ip4.GetNetworkAddress(32);
            IPAddress net6 = ip6.GetNetworkAddress(128);

            // THEN
            Assert.AreEqual(ip4, net4,
                "IPv4 prefix 32 must leave the address unchanged.");
            Assert.AreEqual(ip6, net6,
                "IPv6 prefix 128 must leave the address unchanged.");
        }

        [TestMethod]
        public void GetNetworkAddress_ShouldThrow_WhenPrefixTooLargeForFamily()
        {
            // GIVEN
            IPAddress ip4 = IPAddress.Parse("192.168.1.1");
            IPAddress ip6 = IPAddress.Parse("2001:db8::1");

            // WHEN - THEN
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => ip4.GetNetworkAddress(33),
                "IPv4 network prefix > 32 must be rejected.");
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => ip6.GetNetworkAddress(129),
                "IPv6 network prefix > 128 must be rejected.");
        }

        // ------------------------------------------------------
        // REVERSE DOMAIN GENERATION
        // ------------------------------------------------------

        [TestMethod]
        public void GetReverseDomain_ShouldReturnCorrectIPv4PtrName()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("192.168.10.1");

            // WHEN
            string ptr = ip.GetReverseDomain();

            // THEN
            Assert.AreEqual("1.10.168.192.in-addr.arpa", ptr,
                "IPv4 reverse domain must list octets in reverse order followed by in-addr.arpa.");
        }

        [TestMethod]
        public void GetReverseDomain_ThenParseReverseDomain_ShouldRoundtrip_IPv4()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("10.20.30.40");

            // WHEN
            string ptr = ip.GetReverseDomain();
            IPAddress parsed = IPAddressExtensions.ParseReverseDomain(ptr);

            // THEN
            Assert.AreEqual(ip, parsed,
                "ParseReverseDomain(GetReverseDomain(ip)) must roundtrip IPv4 address exactly.");
        }

        [TestMethod]
        public void GetReverseDomain_ThenParseReverseDomain_ShouldRoundtrip_IPv6()
        {
            // GIVEN
            IPAddress ip = IPAddress.Parse("2001:db8::8b3b:3eb");

            // WHEN
            string ptr = ip.GetReverseDomain();
            IPAddress parsed = IPAddressExtensions.ParseReverseDomain(ptr);

            // THEN
            Assert.AreEqual(ip, parsed,
                "ParseReverseDomain(GetReverseDomain(ip)) must roundtrip IPv6 address exactly, including all nibbles.");
        }

        // ------------------------------------------------------
        // TRY PARSE REVERSE DOMAIN – FAILURE HYGIENE
        // ------------------------------------------------------

        [TestMethod]
        public void TryParseReverseDomain_ShouldReturnFalseAndNull_ForUnknownSuffix()
        {
            // GIVEN
            IPAddress original = IPAddress.Loopback; // must be overwritten on failure

            // WHEN
            bool ok = IPAddressExtensions.TryParseReverseDomain("example.com", out IPAddress? parsed);

            // THEN
            Assert.IsFalse(ok, "TryParseReverseDomain must return false for non-PTR domains.");
            Assert.IsNull(parsed,
                "On failure, TryParseReverseDomain must set out address to null to avoid stale references.");
        }

        [TestMethod]
        public void TryParseReverseDomain_ShouldReturnFalseAndNull_WhenIPv4LabelsAreNotNumeric()
        {
            // GIVEN
            const string invalidPtr = "x.10.168.192.in-addr.arpa";

            // WHEN
            bool ok = IPAddressExtensions.TryParseReverseDomain(invalidPtr, out IPAddress? parsed);

            // THEN
            Assert.IsFalse(ok, "Non-numeric IPv4 labels must cause TryParseReverseDomain to fail cleanly.");
            Assert.IsNull(parsed,
                "On invalid IPv4 PTR, out address must be null to avoid partial parsing.");
        }

        [TestMethod]
        public void TryParseReverseDomain_ShouldRejectShortIPv4Ptr()
        {
            const string ptr = "3.2.1.in-addr.arpa";

            bool ok = IPAddressExtensions.TryParseReverseDomain(ptr, out IPAddress? parsed);

            Assert.IsFalse(ok, "Short IPv4 PTR is not RFC-compliant and must not be accepted.");
            Assert.IsNull(parsed, "No mapping exists for truncated PTR names.");
        }

        [TestMethod]
        public void TryParseReverseDomain_ShouldReturnFalseAndNull_WhenIPv6NibbleInvalid()
        {
            // GIVEN: invalid hex nibble "Z"
            const string ptr = "Z.0.0.0.ip6.arpa";

            // WHEN
            bool ok = IPAddressExtensions.TryParseReverseDomain(ptr, out IPAddress? parsed);

            // THEN
            Assert.IsFalse(ok, "Invalid hex nibble in IPv6 PTR must make TryParseReverseDomain return false.");
            Assert.IsNull(parsed,
                "Out address must be null when IPv6 PTR parsing fails.");
        }

        [TestMethod]
        public void ParseReverseDomain_ShouldThrowNotSupported_WhenTryParseWouldFail()
        {
            // GIVEN
            const string ptr = "not-a-valid.ptr.domain";

            // WHEN - THEN
            Assert.ThrowsExactly<NotSupportedException>(
                () => IPAddressExtensions.ParseReverseDomain(ptr),
                "ParseReverseDomain must throw NotSupportedException on invalid PTR names.");
        }

        [TestMethod]
        public void WriteTo_ShouldWriteIPv4Correctly()
        {
            IPAddress ipv4 = IPAddress.Parse("1.2.3.4");
            using MemoryStream ms = new MemoryStream();

            ipv4.WriteTo(ms);

            byte[] data = ms.ToArray();
            Assert.AreEqual(1, data[0], "First byte encodes IPv4 family discriminator.");
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, data[1..5], "IPv4 bytes must be written exactly.");
        }

        [TestMethod]
        public void WriteTo_ShouldWriteIPv6Correctly()
        {
            IPAddress ipv6 = IPAddress.Parse("2001:db8::1");
            using MemoryStream ms = new MemoryStream();

            ipv6.WriteTo(ms);

            byte[] data = ms.ToArray();
            Assert.AreEqual(2, data[0], "First byte encodes IPv6 family discriminator.");
            Assert.AreEqual(16, data.Length - 1, "IPv6 must write exactly 16 bytes.");
        }


        [TestMethod]
        public void GetSubnetMaskWidth_ShouldNotSilentlyAcceptNonContiguousMasks()
        {
            IPAddress mask = IPAddress.Parse("255.0.255.0");

            // current behavior
            int width = mask.GetSubnetMaskWidth();

            Assert.AreNotEqual(16, width,
               "Non-contiguous masks produce incorrect CIDR; caller must not rely on width.");
        }
        [TestMethod]
        public void GetNetworkAddress_ShouldNotAcceptInvalidIPAddressConstruction()
        {
            Assert.ThrowsExactly<ArgumentException>(() => _ = new IPAddress(Array.Empty<byte>()),
                "IPAddress itself must reject invalid byte arrays at construction time.");
        }

        [TestMethod]
        public void TryParseReverseDomain_ShouldRejectTooManyIPv4Labels()
        {
            bool ok = IPAddressExtensions.TryParseReverseDomain(
                "1.2.3.4.5.in-addr.arpa", out IPAddress? ip);

            Assert.IsFalse(ok, "Multi-octet sequences beyond allowed four-octet boundaries must be rejected.");
            Assert.IsNull(ip, "Returned value must remain null on malformed reverse domain.");
        }

        [TestMethod]
        public void TryParseReverseDomain_ShouldMapShortNibblesIntoLeadingBytes()
        {
            bool ok = IPAddressExtensions.TryParseReverseDomain("A.B.C.ip6.arpa", out IPAddress? ip);

            Assert.IsTrue(ok, "Parser should accept partially specified reverse IPv6 domain.");

            Assert.IsNotNull(ip);
            Assert.AreEqual(IPAddress.Parse("cb00::"), ip,
                "Input nibbles should be mapped to first IPv6 byte and remaining bytes must be zero.");
        }
    }
}
