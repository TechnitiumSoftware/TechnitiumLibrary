using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
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

        [Fact]
        public void GetArray_ReadsJsonArrayElementDirectly()
        {
            using JsonDocument doc = JsonDocument.Parse("[\"x\",\"y\"]");

            Assert.Equal(new[] { "x", "y" }, doc.RootElement.GetArray());
        }

        [Fact]
        public void TryReadMethods_ReturnFalseWhenPropertyMissing()
        {
            using JsonDocument doc = JsonDocument.Parse("{}");
            JsonElement root = doc.RootElement;

            Assert.False(root.TryReadArray("missing", out string[] array));
            Assert.Null(array);
            Assert.False(root.TryReadArray<int>("missing", int.Parse, out int[] parsed));
            Assert.Null(parsed);
            Assert.False(root.TryReadArray<int>("missing", e => e.GetInt32(), out int[] elements));
            Assert.Null(elements);
            Assert.False(root.TryReadArrayAsSet("missing", out HashSet<string> set));
            Assert.Null(set);
            Assert.False(root.TryReadArrayAsMap<string, int>("missing", e => Tuple.Create(e.GetProperty("k").GetString()!, e.GetProperty("v").GetInt32()), out Dictionary<string, int> map));
            Assert.Null(map);
            Assert.False(root.TryReadObjectAsMap<string, int>("missing", (k, v) => Tuple.Create(k, v.GetInt32()), out Dictionary<string, int> objectMap));
            Assert.Null(objectMap);
        }

        [Fact]
        public void ReadArrayOverloads_ParseStringsElementsSetsAndMaps()
        {
            using JsonDocument doc = JsonDocument.Parse("{\"numbers\":[\"1\",\"2\"],\"objects\":[{\"k\":\"a\",\"v\":1},{\"k\":\"b\",\"v\":2},null],\"set\":[\"a\",\"a\",\"b\"]}");
            JsonElement root = doc.RootElement;

            Assert.Equal(new[] { 1, 2 }, root.ReadArray("numbers", int.Parse));
            Assert.True(root.TryReadArray("numbers", int.Parse, out int[] numbers));
            Assert.Equal(new[] { 1, 2 }, numbers);
            Assert.Equal(new[] { 1, 2 }, root.ReadArray("numbers", e => int.Parse(e.GetString()!)));
            Assert.True(root.TryReadArray("numbers", e => int.Parse(e.GetString()!), out int[] elements));
            Assert.Equal(new[] { 1, 2 }, elements);

            HashSet<string> set = root.ReadArrayAsSet("set");
            Assert.Equal(new[] { "a", "b" }, set.OrderBy(x => x).ToArray());
            Assert.True(root.TryReadArrayAsSet("set", out HashSet<string> set2));
            Assert.Equal(set, set2);

            Dictionary<string, int> map = root.ReadArrayAsMap("objects", e =>
                e.ValueKind == JsonValueKind.Null ? null : Tuple.Create(e.GetProperty("k").GetString()!, e.GetProperty("v").GetInt32()));
            Assert.Equal(2, map.Count);
            Assert.Equal(2, map["b"]);
            Assert.True(root.TryReadArrayAsMap("objects", e =>
                e.ValueKind == JsonValueKind.Null ? null : Tuple.Create(e.GetProperty("k").GetString()!, e.GetProperty("v").GetInt32()), out Dictionary<string, int> map2));
            Assert.Equal(map, map2);
        }

        [Fact]
        public void NullArrays_ReturnNullAndInvalidKindsThrow()
        {
            using JsonDocument doc = JsonDocument.Parse("{\"value\":5,\"items\":null}");
            JsonElement root = doc.RootElement;

            Assert.Null(root.ReadArray("items"));
            Assert.Null(root.ReadArray<int>("items", int.Parse));
            Assert.Null(root.ReadArray<int>("items", e => e.GetInt32()));
            Assert.Null(root.ReadArrayAsSet("items"));
            Assert.Null(root.ReadArrayAsMap<string, int>("items", e => Tuple.Create("x", 1)));

            Assert.Throws<InvalidOperationException>(() => root.ReadArray("value"));
            Assert.Throws<InvalidOperationException>(() => root.ReadArray<int>("value", int.Parse));
            Assert.Throws<InvalidOperationException>(() => root.ReadArray<int>("value", e => e.GetInt32()));
            Assert.Throws<InvalidOperationException>(() => root.ReadArrayAsSet("value"));
            Assert.Throws<InvalidOperationException>(() => root.ReadArrayAsMap<string, int>("value", e => Tuple.Create("x", 1)));
            Assert.Throws<InvalidOperationException>(() => root.TryReadObjectAsMap<string, int>("value", (k, v) => Tuple.Create(k, v.GetInt32()), out _));
        }

        [Fact]
        public void TryReadObjectAsMap_CoversObjectNullAndSkippedItems()
        {
            using JsonDocument doc = JsonDocument.Parse("{\"map\":{\"a\":1,\"skip\":2},\"nullMap\":null}");
            JsonElement root = doc.RootElement;

            Assert.True(root.TryReadObjectAsMap("map", (k, v) => k == "skip" ? null : Tuple.Create(k, v.GetInt32()), out Dictionary<string, int> map));
            Assert.Single(map);
            Assert.Equal(1, map["a"]);

            Assert.True(root.TryReadObjectAsMap<string, int>("nullMap", (k, v) => Tuple.Create(k, v.GetInt32()), out Dictionary<string, int> nullMap));
            Assert.Null(nullMap);
        }

        [Fact]
        public void GetPropertyValue_HandlesNumericEnumAndParsedValues()
        {
            using JsonDocument doc = JsonDocument.Parse("{\"name\":\"abc\",\"flag\":true,\"i\":-5,\"u\":5,\"l\":1234567890123,\"kind\":\"Friday\",\"parsed\":\"10\"}");
            JsonElement root = doc.RootElement;

            Assert.Equal("abc", root.GetPropertyValue("name", "default"));
            Assert.Equal(-5, root.GetPropertyValue("i", 0));
            Assert.Equal(5u, root.GetPropertyValue("u", 0u));
            Assert.Equal(1234567890123L, root.GetPropertyValue("l", 0L));
            Assert.Equal(10, root.GetPropertyValue("parsed", int.Parse, 0));
            Assert.Equal(DayOfWeek.Friday, root.GetPropertyEnumValue("kind", DayOfWeek.Monday));

            Assert.False(root.GetPropertyValue("missingBool", false));
            Assert.Equal(6, root.GetPropertyValue("missingInt", 6));
            Assert.Equal(7u, root.GetPropertyValue("missingUInt", 7u));
            Assert.Equal(8L, root.GetPropertyValue("missingLong", 8L));
            Assert.Equal(9, root.GetPropertyValue("missingParsed", int.Parse, 9));
            Assert.Equal(DayOfWeek.Sunday, root.GetPropertyEnumValue("missingEnum", DayOfWeek.Sunday));
        }
    }
}
