using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class DomainEndPointTests
    {
        // ================================================================
        // CONSTRUCTOR – SUCCESS CASES
        // ================================================================

        [TestMethod]
        public void Constructor_ShouldAcceptAsciiDomain_AndStorePort()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 853);

            Assert.AreEqual("example.com", ep.Address,
                "Constructor must preserve ASCII domain without alteration.");
            Assert.AreEqual(853, ep.Port,
                "Constructor must store provided port value exactly.");
            Assert.AreEqual(AddressFamily.Unspecified, ep.AddressFamily,
                "Domain endpoints must remain AddressFamily.Unspecified for defensive correctness.");
        }

        [TestMethod]
        public void Constructor_ShouldNormalizeUnicodeToAscii()
        {
            DomainEndPoint ep = new DomainEndPoint("münich.de", 443);

            Assert.AreEqual("xn--mnich-kva.de", ep.Address,
                "Constructor must normalize Unicode domain into IDN ASCII equivalent.");
            Assert.AreEqual(443, ep.Port,
                "Port must remain exactly as provided.");
        }


        // ================================================================
        // CONSTRUCTOR – FAILURE CASES
        // ================================================================

        [TestMethod]
        public void Constructor_ShouldFailFast_WhenAddressIsNull()
        {
            ArgumentNullException ex = Assert.ThrowsExactly<ArgumentNullException>(
                () => _ = new DomainEndPoint(null!, 53),
                "Null address must be rejected to prevent partially invalid instance.");

            Assert.AreEqual("address", ex.ParamName,
                "Thrown exception must identify the faulty parameter.");
        }

        [TestMethod]
        public void Constructor_ShouldRejectIPv4Literal()
        {
            Assert.ThrowsExactly<ArgumentException>(
                () => _ = new DomainEndPoint("192.168.1.1", 80),
                "Constructor must reject IP literals to preserve domain-only invariant.");
        }

        [TestMethod]
        public void Constructor_ShouldRejectObviouslyMalformedDomain()
        {
            DnsClientException ex = Assert.ThrowsExactly<DnsClientException>(
                () => _ = new DomainEndPoint("exa mple.com", 853),
                "Constructor must reject syntactically invalid domain by failing fast through validation-layer exception.");

            Assert.Contains("exa mple.com", ex.Message, "Thrown validation exception must include original input for caller diagnostic correctness.");
        }


        // ================================================================
        // TRY PARSE – SUCCESS CASES
        // ================================================================

        [TestMethod]
        public void TryParse_ShouldParseDomainWithoutPort_DefaultPortZero()
        {
            bool ok = DomainEndPoint.TryParse("example.com", out DomainEndPoint? ep);

            Assert.IsTrue(ok, "TryParse must succeed for valid domain without port.");
            Assert.IsNotNull(ep, "Successful TryParse must produce a concrete instance.");
            Assert.AreEqual("example.com", ep.Address,
                "Domain segment must remain unchanged.");
            Assert.AreEqual(0, ep.Port,
                "No explicit port must result in Port=0.");
        }

        [TestMethod]
        public void TryParse_ShouldParseDomainWithPort()
        {
            bool ok = DomainEndPoint.TryParse("example.com:445", out DomainEndPoint? ep);

            Assert.IsTrue(ok,
                "TryParse must succeed for expected domain:port format.");
            Assert.AreEqual("example.com", ep!.Address);
            Assert.AreEqual(445, ep.Port);
        }

        [TestMethod]
        public void TryParse_ShouldNormalizeUnicodeDomain()
        {
            bool ok = DomainEndPoint.TryParse("münich.de:80", out DomainEndPoint? ep);

            Assert.IsTrue(ok, "Valid Unicode domain must be accepted.");
            Assert.AreEqual("xn--mnich-kva.de", ep!.Address,
                "Unicode must normalize predictably to ASCII.");
            Assert.AreEqual(80, ep.Port,
                "Port must reflect provided integer value.");
        }

        [TestMethod]
        public void TryParse_ShouldRoundtripSuccessfully()
        {
            const string original = "example.com:853";

            Assert.IsTrue(DomainEndPoint.TryParse(original, out DomainEndPoint? ep1),
                "TryParse must succeed on valid input.");

            string serialized = ep1!.ToString();
            Assert.IsTrue(DomainEndPoint.TryParse(serialized, out DomainEndPoint? ep2),
                "Re-parsing output must succeed.");

            Assert.AreEqual(ep1.Address, ep2!.Address,
                "Roundtrip must preserve domain identity exactly.");
            Assert.AreEqual(ep1.Port, ep2.Port,
                "Roundtrip must preserve port identity exactly.");
        }


        // ================================================================
        // TRY PARSE – FAILURE CASES
        // ================================================================

        [TestMethod]
        public void TryParse_ShouldFail_WhenInputIsNull()
        {
            bool ok = DomainEndPoint.TryParse(null, out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Null value cannot represent valid domain endpoint.");
            Assert.IsNull(ep, "Endpoint must remain null when parsing fails.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenEmptyString()
        {
            bool ok = DomainEndPoint.TryParse("", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Empty string cannot represent valid domain endpoint.");
            Assert.IsNull(ep, "Endpoint must remain null when parsing fails.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenWhitespaceOnly()
        {
            bool ok = DomainEndPoint.TryParse("    ", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Whitespace-only input cannot represent valid domain endpoint.");
            Assert.IsNull(ep, "Result object must remain null on failure.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenTooManyColons()
        {
            bool ok = DomainEndPoint.TryParse("a:b:c", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Multiple separators violate predictable domain:port format.");
            Assert.IsNull(ep, "Endpoint must remain null to avoid partially valid identity.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenDomainIsIPAddress()
        {
            bool ok = DomainEndPoint.TryParse("127.0.0.1:81", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "IP literal parsing must be rejected consistently.");
            Assert.IsNull(ep, "Null endpoint is required defensive failure output.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenNonNumericPort()
        {
            bool ok = DomainEndPoint.TryParse("example.com:abc", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Port must parse strictly as numeric.");
            Assert.IsNull(ep, "Failure scenario must not yield partially created endpoint.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenPortOutOfRange()
        {
            bool ok = DomainEndPoint.TryParse("example.com:70000", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Ports exceeding UInt16 range cannot be treated as valid.");
            Assert.IsNull(ep, "No endpoint must be generated.");
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenDomainContainsSpaces()
        {
            bool ok = DomainEndPoint.TryParse("exa mple.com:53", out DomainEndPoint? ep);

            Assert.IsFalse(ok, "Invalid domain format must not succeed.");
            Assert.IsNull(ep, "Endpoint must remain null upon failure.");
        }


        // ================================================================
        // ADDRESS BYTES
        // ================================================================

        [TestMethod]
        public void GetAddressBytes_MustReturnLengthPrefixedAsciiBytes()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 80);
            byte[] result = ep.GetAddressBytes();

            byte[] ascii = Encoding.ASCII.GetBytes("example.com");

            Assert.AreEqual(ascii.Length, result[0],
                "Length prefix must exactly match ASCII length of the address.");
            for (int i = 0; i < ascii.Length; i++)
            {
                Assert.AreEqual(ascii[i], result[i + 1],
                    $"Byte index {i} must reflect ASCII domain payload.");
            }
        }

        [TestMethod]
        public void GetAddressBytes_MustReturnIndependentBuffers()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 80);

            byte[] a = ep.GetAddressBytes();
            a[1] ^= 0xFF;

            byte[] b = ep.GetAddressBytes();

            Assert.AreNotEqual(a[1], b[1],
                "Returned byte arrays must not expose internal mutable buffers.");
        }


        // ================================================================
        // EQUALITY & HASH
        // ================================================================

        [TestMethod]
        public void Equals_MustBeCaseInsensitiveForDomain_AndStrictOnPort()
        {
            DomainEndPoint ep1 = new DomainEndPoint("Example.com", 443);
            DomainEndPoint ep2 = new DomainEndPoint("example.com", 443);
            DomainEndPoint ep3 = new DomainEndPoint("example.com", 853);

            Assert.IsTrue(ep1.Equals(ep2),
                "Domain equality must ignore case differences.");
            Assert.IsFalse(ep1.Equals(ep3),
                "Different ports must break equality even when domain matches.");
        }

        [TestMethod]
        public void GetHashCode_MustBeStableAcrossRepeatedCalls()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 443);

            int h1 = ep.GetHashCode();
            int h2 = ep.GetHashCode();

            Assert.AreEqual(h1, h2,
                "Hash code must remain stable to support predictable dictionary usage.");
        }

        [TestMethod]
        public void Equals_MustReturnFalse_ForDifferentTypeAndNull()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 80);

            Assert.IsFalse(ep.Equals(null),
                "Comparing against null must never produce equality.");
            Assert.IsFalse(ep.Equals("example.com:80"),
                "Comparing against non-endpoint type must not succeed.");
        }


        // ================================================================
        // PROPERTY SETTERS
        // ================================================================

        [TestMethod]
        public void Address_Setter_MustNotCorruptUnrelatedState()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 53);

            ep.Address = "192.168.9.10";

            Assert.AreEqual("192.168.9.10", ep.Address,
                "Setter does not re-validate by design; caller assumes responsibility.");
            Assert.AreEqual(53, ep.Port,
                "Setter mutation must not affect unrelated fields.");
        }

        [TestMethod]
        public void Port_Setter_MustAllowCallerProvidedValueAsIs()
        {
            DomainEndPoint ep = new DomainEndPoint("example.com", 53);

            ep.Port = -1;

            Assert.AreEqual(-1, ep.Port,
                "Setter must store raw caller intent; constraints belong outside endpoint abstraction.");
        }
    }
}
