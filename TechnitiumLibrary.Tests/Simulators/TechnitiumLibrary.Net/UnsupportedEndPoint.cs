using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net
{
    internal sealed class UnsupportedEndPoint : EndPoint
    {
        private readonly AddressFamily _addressFamily;

        public UnsupportedEndPoint(AddressFamily addressFamily)
        {
            _addressFamily = addressFamily;
        }

        public override AddressFamily AddressFamily
        { get { return _addressFamily; } }
    }
}
