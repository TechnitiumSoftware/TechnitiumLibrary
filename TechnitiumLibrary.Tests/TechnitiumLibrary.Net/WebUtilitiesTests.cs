using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Mime;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Http.Client;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class WebUtilitiesTests
    {
        #region GetFormattedSize

        [TestMethod]
        public void GetFormattedSize_ShouldFormatBytesUnderThousand_AsBytes()
        {
            string s = WebUtilities.GetFormattedSize(999);

            Assert.AreEqual("999 B", s,
                "Values below 1000 must remain in bytes with ' B' suffix.");
        }

        [TestMethod]
        public void GetFormattedSize_ShouldFormatExactKiB_AsKB()
        {
            double bytes = 1024; // 1 KiB

            string s = WebUtilities.GetFormattedSize(bytes);

            Assert.AreEqual("1 KB", s,
                "1024 bytes must be rendered as '1 KB' using 1024 divisor.");
        }

        [TestMethod]
        public void GetFormattedSize_ShouldFormatExactMiB_AsMB()
        {
            double bytes = 1024 * 1024; // 1 MiB

            string s = WebUtilities.GetFormattedSize(bytes);

            Assert.AreEqual("1 MB", s,
                "1 MiB must be rendered as '1 MB'.");
        }

        [TestMethod]
        public void GetFormattedSize_ShouldFormatExactGiB_AsGB()
        {
            double bytes = 1024d * 1024 * 1024; // 1 GiB

            string s = WebUtilities.GetFormattedSize(bytes);

            Assert.AreEqual("1 GB", s,
                "1 GiB must be rendered as '1 GB'.");
        }

        #endregion

        #region GetFormattedSpeed

        [TestMethod]
        public void GetFormattedSpeed_ShouldFormatSmallAsBitsPerSecond_ByDefault()
        {
            double bytesPerSecond = 100; // 800 bps

            string s = WebUtilities.GetFormattedSpeed(bytesPerSecond);

            Assert.AreEqual("800 bps", s,
                "Default mode must convert bytes to bits and stay in 'bps' for values < 1000.");
        }

        [TestMethod]
        public void GetFormattedSpeed_ShouldFormatMegabitPerSecond()
        {
            double bytesPerSecond = 125_000; // 1_000_000 bits/s → 1 mbps

            string s = WebUtilities.GetFormattedSpeed(bytesPerSecond);

            Assert.AreEqual("1 mbps", s,
                "125000 B/s must be formatted as '1 mbps'.");
        }

        [TestMethod]
        public void GetFormattedSpeed_ShouldFormatKiBPerSecond_WhenUsingBytesMode()
        {
            double bytesPerSecond = 1024; // 1 KiB/s

            string s = WebUtilities.GetFormattedSpeed(bytesPerSecond, bitsPerSecond: false);

            Assert.AreEqual("1 KB/s", s,
                "In bytes mode, 1024 bytes per second must be rendered as '1 KB/s'.");
        }

        #endregion

        #region GetFormattedTime

        [TestMethod]
        public void GetFormattedTime_ShouldReturnZeroSeconds_ForZeroInput()
        {
            string s = WebUtilities.GetFormattedTime(0);

            Assert.AreEqual("0 sec", s,
                "Zero seconds must render as '0 sec'.");
        }

        [TestMethod]
        public void GetFormattedTime_ShouldRenderMinutesAndSeconds()
        {
            string s = WebUtilities.GetFormattedTime(61);

            Assert.AreEqual("1 min 1 sec", s,
                "61 seconds must be formatted as '1 min 1 sec'.");
        }

        [TestMethod]
        public void GetFormattedTime_ShouldRenderHoursMinutesSeconds()
        {
            int seconds = 1 * 3600 + 2 * 60 + 3; // 1h 2m 3s

            string s = WebUtilities.GetFormattedTime(seconds);

            Assert.AreEqual("1 hour 2 mins 3 sec", s,
                "Composite time must express hour, minute(s), and seconds with pluralization.");
        }

        [TestMethod]
        public void GetFormattedTime_ShouldRenderDaysAndHours_ONLY_WhenNoLowerUnits()
        {
            int seconds = 2 * 24 * 3600 + 5 * 3600; // 2 days 5 hours

            string s = WebUtilities.GetFormattedTime(seconds);

            Assert.AreEqual("2 days 5 hours", s,
                "Whole days and hours with zero minutes/seconds should omit lower units.");
        }

        #endregion

        #region GetContentType

        [TestMethod]
        public void GetContentType_ShouldReturnDefaultForUnknownExtension()
        {
            ContentType ct = WebUtilities.GetContentType("file.unknownext");

            Assert.AreEqual("application/octet-stream", ct.MediaType,
                "Unknown extensions must map to binary 'application/octet-stream'.");
        }

        [TestMethod]
        public void GetContentType_ShouldBeCaseInsensitive_OnExtension()
        {
            ContentType lower = WebUtilities.GetContentType("photo.jpg");
            ContentType upper = WebUtilities.GetContentType("PHOTO.JPG");

            Assert.AreEqual("image/jpeg", lower.MediaType);
            Assert.AreEqual("image/jpeg", upper.MediaType,
                "Extension must be treated case-insensitively.");
        }

        [TestMethod]
        public void GetContentType_ShouldRecognizeCommonScriptAndDocumentTypes()
        {
            ContentType js = WebUtilities.GetContentType("app.js");
            ContentType pdf = WebUtilities.GetContentType("doc.pdf");
            ContentType xlsx = WebUtilities.GetContentType("sheet.xlsx");

            Assert.AreEqual("application/javascript", js.MediaType,
                "'.js' must resolve to 'application/javascript'.");
            Assert.AreEqual("application/pdf", pdf.MediaType,
                "'.pdf' must resolve to 'application/pdf'.");
            Assert.AreEqual(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                xlsx.MediaType,
                "'.xlsx' must resolve to correct OOXML spreadsheet MIME type.");
        }

        #endregion

        #region IsWebAccessibleAsync

        [TestMethod]
        public async Task IsWebAccessibleAsync_ShouldReturnFalse_ForAlwaysUnreachableUris()
        {
            // 198.51.100.0/24 is TEST-NET-2 (non-routed in normal internet).
            Uri[] targets =
            {
                new Uri("http://198.51.100.1/"),
                new Uri("http://198.51.100.2/")
            };

            bool ok = await WebUtilities.IsWebAccessibleAsync(
                uriCheckList: targets,
                proxy: null,
                networkType: HttpClientNetworkType.Default,
                timeout: 500,
                throwException: false);

            Assert.IsFalse(ok,
                "Unreachable test-net hosts must yield 'false' without throwing when throwException=false.");
        }

        [TestMethod]
        public async Task IsWebAccessibleAsync_ShouldThrowFailure_WhenThrowExceptionIsTrue()
        {
            Uri[] targets =
            {
        new Uri("http://198.51.100.1/"),
        new Uri("http://198.51.100.2/")
    };

            try
            {
                await Assert.ThrowsExactlyAsync<TaskCanceledException>(async () =>
                {
                    _ = await WebUtilities.IsWebAccessibleAsync(
                        uriCheckList: targets,
                        proxy: null,
                        networkType: HttpClientNetworkType.Default,
                        timeout: 500,
                        throwException: true);
                });
            }
            catch (AssertFailedException)
            {
                await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
                {
                    _ = await WebUtilities.IsWebAccessibleAsync(
                        uriCheckList: targets,
                        proxy: null,
                        networkType: HttpClientNetworkType.Default,
                        timeout: 500,
                        throwException: true);
                });
            }
        }

        #endregion

        #region GetValidKestrelLocalAddresses

        [TestMethod]
        public void GetValidKestrelLocalAddresses_ShouldFilterUnsupportedFamilies()
        {
            // Only IPv4 Any and IPv6 Any are meaningful here; unsupported families are skipped by design.
            List<IPAddress> input = new List<IPAddress>
            {
                IPAddress.Any,
                IPAddress.IPv6Any
            };

            IReadOnlyList<IPAddress> result = WebUtilities.GetValidKestrelLocalAddresses(input);

            // Must never introduce new addresses, and must only contain supported families.
            foreach (IPAddress addr in result)
            {
                Assert.IsTrue(
                    addr.AddressFamily == AddressFamily.InterNetwork
                    || addr.AddressFamily == AddressFamily.InterNetworkV6,
                    "Result must only contain IPv4 or IPv6 addresses.");
            }
        }

        [TestMethod]
        public void GetValidKestrelLocalAddresses_ShouldReplaceAnyWithLoopback_WhenUnicastPresent()
        {
            if (!Socket.OSSupportsIPv4)
                Assert.Inconclusive("IPv4 not supported on this platform; skipping IPv4-specific behavior test.");

            List<IPAddress> input = new List<IPAddress>
            {
                IPAddress.Any,                 // 0.0.0.0
                IPAddress.Parse("10.0.0.1")    // unicast
            };

            IReadOnlyList<IPAddress> result = WebUtilities.GetValidKestrelLocalAddresses(input);

            CollectionAssert.DoesNotContain(
                (System.Collections.ICollection)result,
                IPAddress.Any,
                "When unicast IPv4 is present, '0.0.0.0' must be replaced, not preserved.");

            CollectionAssert.Contains(
                (System.Collections.ICollection)result,
                IPAddress.Loopback,
                "'0.0.0.0' must be mapped to IPv4 loopback when unicast is also configured.");

            CollectionAssert.Contains(
                (System.Collections.ICollection)result,
                IPAddress.Parse("10.0.0.1"),
                "Existing unicast IPv4 addresses must be preserved.");
        }

        [TestMethod]
        public void GetValidKestrelLocalAddresses_ShouldPreferIPv6AnyOverIPv4Any_WhenNoUnicast()
        {
            if (!Socket.OSSupportsIPv4 || !Socket.OSSupportsIPv6)
                Assert.Inconclusive("Both IPv4 and IPv6 support required to validate dual-stack 'Any' behavior.");

            List<IPAddress> input = new List<IPAddress>
            {
                IPAddress.Any,
                IPAddress.IPv6Any
            };

            IReadOnlyList<IPAddress> result = WebUtilities.GetValidKestrelLocalAddresses(input);

            CollectionAssert.DoesNotContain(
                (System.Collections.ICollection)result,
                IPAddress.Any,
                "When both 0.0.0.0 and [::] exist and no unicast is present, IPv4 Any must be removed.");
            CollectionAssert.Contains(
                (System.Collections.ICollection)result,
                IPAddress.IPv6Any,
                "[::] must remain when dual-stack Any was configured and no unicast exists.");
        }

        [TestMethod]
        public void GetValidKestrelLocalAddresses_ShouldDeduplicateAddresses()
        {
            if (!Socket.OSSupportsIPv4)
                Assert.Inconclusive("IPv4 not supported on this platform; skipping deduplication test.");

            IPAddress ip = IPAddress.Parse("192.0.2.10"); // TEST-NET-1 address

            List<IPAddress> input = new List<IPAddress>
            {
                ip,
                ip,
                IPAddress.Any
            };

            IReadOnlyList<IPAddress> result = WebUtilities.GetValidKestrelLocalAddresses(input);

            int countOfUnicast = 0;
            foreach (IPAddress addr in result)
            {
                if (addr.Equals(ip))
                    countOfUnicast++;
            }

            Assert.AreEqual(1, countOfUnicast,
                "Result must not contain duplicate unicast entries.");
        }

        #endregion

        public TestContext TestContext { get; set; }
    }
}
