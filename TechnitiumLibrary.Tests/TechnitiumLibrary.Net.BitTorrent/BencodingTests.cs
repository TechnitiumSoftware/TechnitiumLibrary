using System.Collections.Generic;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class BencodingTests
    {
        [Fact]
        public void StringRoundtrips()
        {
            Bencoding value = new Bencoding(BencodingType.String, "spam");
            using MemoryStream stream = new MemoryStream();

            value.Encode(stream);

            Assert.Equal("4:spam", Encoding.ASCII.GetString(stream.ToArray()));
            Bencoding decoded = Bencoding.Decode(stream.ToArray());
            Assert.Equal(BencodingType.String, decoded.Type);
            Assert.Equal("spam", decoded.ValueString);
            Assert.Equal(decoded.Value, decoded.Value as byte[]);
        }

        [Fact]
        public void ByteStringRoundtrips()
        {
            byte[] bytes = [0, 1, 2, 255];
            Bencoding value = new Bencoding(BencodingType.String, bytes);
            using MemoryStream stream = new MemoryStream();

            value.Encode(stream);
            stream.Position = 0;

            Bencoding decoded = Bencoding.Decode(stream);

            Assert.Equal(bytes, decoded.Value as byte[]);
        }

        [Fact]
        public void IntegerRoundtrips()
        {
            Bencoding value = new Bencoding(BencodingType.Integer, -42L);
            using MemoryStream stream = new MemoryStream();

            value.Encode(stream);

            Assert.Equal("i-42e", Encoding.ASCII.GetString(stream.ToArray()));
            Assert.Equal(-42L, Bencoding.Decode(stream.ToArray()).ValueInteger);
        }

        [Fact]
        public void ListRoundtrips()
        {
            Bencoding value = new Bencoding(BencodingType.List, new List<Bencoding>
            {
                new Bencoding(BencodingType.String, "alpha"),
                new Bencoding(BencodingType.Integer, 7L)
            });
            using MemoryStream stream = new MemoryStream();

            value.Encode(stream);
            stream.Position = 0;

            Bencoding decoded = Bencoding.Decode(stream);

            Assert.Equal(BencodingType.List, decoded.Type);
            Assert.Equal("alpha", decoded.ValueList[0].ValueString);
            Assert.Equal(7L, decoded.ValueList[1].ValueInteger);
        }

        [Fact]
        public void DictionaryRoundtrips()
        {
            Bencoding value = new Bencoding(
                BencodingType.Dictionary,
                new Dictionary<string, Bencoding>
                {
                    ["answer"] = new Bencoding(BencodingType.Integer, 42L),
                    ["items"] = new Bencoding(BencodingType.List, new List<Bencoding>
                    {
                        new Bencoding(BencodingType.String, "alpha"),
                        new Bencoding(BencodingType.Integer, -1L)
                    })
                });

            using MemoryStream stream = new MemoryStream();
            value.Encode(stream);
            stream.Position = 0;

            Bencoding decoded = Bencoding.Decode(stream);

            Assert.Equal(BencodingType.Dictionary, decoded.Type);
            Assert.Equal(42L, decoded.ValueDictionary["answer"].ValueInteger);
            Assert.Equal("alpha", decoded.ValueDictionary["items"].ValueList[0].ValueString);
            Assert.Equal(-1L, decoded.ValueDictionary["items"].ValueList[1].ValueInteger);
        }

        [Fact]
        public void DecodeReturnsNullForEndMarkerInsideCollections()
        {
            using MemoryStream stream = new MemoryStream(new byte[] { (byte)'e' });

            Assert.Null(Bencoding.Decode(stream));
        }

        [Fact]
        public void DecodeRejectsTruncatedIntegerAndString()
        {
            Assert.Throws<EndOfStreamException>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("i42")));
            Assert.ThrowsAny<Exception>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("4:abc")));
            Assert.ThrowsAny<Exception>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("x")));
        }

        [Fact]
        public void DecodeRejectsDictionaryWithNonStringKey()
        {
            Assert.ThrowsAny<Exception>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("di1e4:spame")));
        }

        [Fact]
        public void DecodeThrowsOnEmptyStream()
        {
            Assert.Throws<EndOfStreamException>(() => Bencoding.Decode(new MemoryStream()));
        }

        [Fact]
        public void EncodeRejectsInvalidType()
        {
            Bencoding value = new Bencoding((BencodingType)99, null);

            Assert.ThrowsAny<Exception>(() => value.Encode(new MemoryStream()));
        }
    }
}
