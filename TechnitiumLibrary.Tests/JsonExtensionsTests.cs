using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;

namespace TechnitiumLibrary.Tests
{
    public class JsonExtensionsTests
    {
        [Fact]
        public void ReadArrayAndSet_And_GetPropertyValue()
        {
            using var doc = JsonDocument.Parse("{\"arr\":[\"a\",\"b\"], \"val\": 5, \"flag\": true}");
            var root = doc.RootElement;

            var arr = root.ReadArray("arr");
            Assert.Equal(new string[] { "a", "b" }, arr);

            Assert.True(root.TryReadArray("arr", out string[] arr2));
            Assert.Equal(arr, arr2);

            Assert.Equal(5, root.GetPropertyValue("val", 0));
            Assert.True(root.GetPropertyValue("flag", false));
            Assert.Equal("x", root.GetPropertyValue("missing", "x"));
        }

        [Fact]
        public void ReadObjectAsMap_WritesStringArray()
        {
            using var doc = JsonDocument.Parse("{\"map\": {\"k1\": \"v1\"}}");
            var root = doc.RootElement;

            var map = root.ReadObjectAsMap<string, string?>("map", (k, v) => Tuple.Create(k, v.GetString()));
            Assert.Equal("v1", map["k1"]);

            using var ms = new MemoryStream();
            using var writer = new Utf8JsonWriter(ms);
            writer.WriteStartObject();
            writer.WriteStringArray("arr", new List<int> { 1, 2 });
            writer.WriteEndObject();
            writer.Flush();
            // ensure method runs without throwing
        }
    }
}
