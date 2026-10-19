using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.UPnP;
using TechnitiumLibrary.Net.UPnP.Networking;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.UPnP
{
    public class UPnPProjectTests
    {
        [Fact]
        public void GenericPortMappingEntry_ExposesExternalAndInternalEndpointData()
        {
            IPAddress remoteHost = IPAddress.Parse("203.0.113.10");
            IPAddress internalClient = IPAddress.Parse("192.168.1.5");
            GenericPortMappingEntry entry = new GenericPortMappingEntry(
                remoteHost,
                externalPort: 8443,
                ProtocolType.Tcp,
                internalPort: 443,
                internalClient,
                enabled: true,
                description: "https",
                leaseDuration: 3600);

            Assert.Equal(new IPEndPoint(remoteHost, 8443), entry.ExternalEP);
            Assert.Equal(new IPEndPoint(internalClient, 443), entry.InternalEP);
            Assert.Equal(ProtocolType.Tcp, entry.Protocol);
            Assert.True(entry.Enabled);
            Assert.Equal("https", entry.Description);
            Assert.Equal(3600, entry.LeaseDuration);
        }

        [Fact]
        public void UPnPException_PreservesMessageAndInnerException()
        {
            Exception inner = new Exception("inner");
            UPnPException ex = new UPnPException("failed", inner);

            Assert.Equal("failed", ex.Message);
            Assert.Same(inner, ex.InnerException);
        }
    }
}
