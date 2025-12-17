using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text.Json;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class JsonExtensionsTests
    {
        private static JsonElement ToElement(string json)
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }

        // ------------------------------
        // ARRAY READING (STRING)
        // ------------------------------

        [TestMethod]
        public void GetArray_ShouldReturnStringArray_WhenArrayExists()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": ["a", "b", "c"] }""");

            // WHEN
            string[] result = json.ReadArray("values");

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual("a", result[0]);
            Assert.AreEqual("b", result[1]);
            Assert.AreEqual("c", result[2]);
        }

        [TestMethod]
        public void GetArray_ShouldReturnNull_WhenJsonContainsNull()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": null }""");

            // WHEN
            string[] result = json.ReadArray("values");

            // THEN
            Assert.IsNull(result);
        }

        [TestMethod]
        public void GetArray_ShouldThrow_WhenPropertyIsNotArrayOrNull()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": 123 }""");

            // WHEN–THEN
            Assert.ThrowsExactly<InvalidOperationException>(() => json.ReadArray("values"));
        }

        // ------------------------------
        // ARRAY READING WITH MAPPING (string→int)
        // ------------------------------

        [TestMethod]
        public void ReadArray_WithConverter_ShouldReturnMappedArray()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": ["1","2","3"] }""");

            // WHEN
            int[] result = json.ReadArray("values", int.Parse);

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(1, result[0]);
            Assert.AreEqual(2, result[1]);
            Assert.AreEqual(3, result[2]);
        }

        [TestMethod]
        public void ReadArray_WithConverter_ShouldThrow_WhenConverterThrows()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": ["bad"] }""");

            // WHEN–THEN
            Assert.ThrowsExactly<FormatException>(() =>
                json.ReadArray("values", s => int.Parse(s)));
        }

        [TestMethod]
        public void TryReadArray_WithConverter_ShouldReturnFalse_WhenPropertyMissing()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "other": [1,2] }""");

            // WHEN
            bool result = json.TryReadArray("values", int.Parse, out int[]? array);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(array);
        }

        [TestMethod]
        public void TryReadArray_WithConverter_ShouldReturnTrue_WhenArrayExists()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": ["10","20"] }""");

            // WHEN
            bool result = json.TryReadArray("values", int.Parse, out int[]? array);

            // THEN
            Assert.IsTrue(result);
            Assert.HasCount(2, array);
            Assert.AreEqual(10, array[0]);
            Assert.AreEqual(20, array[1]);
        }

        // ------------------------------
        // READ SET
        // ------------------------------

        [TestMethod]
        public void ReadArrayAsSet_ShouldReturnHashSetOfUniqueValues()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": ["a","b","a"] }""");

            // WHEN
            System.Collections.Generic.HashSet<string> result = json.ReadArrayAsSet("values");

            // THEN
            Assert.HasCount(2, result);
            Assert.Contains("a", result);
            Assert.Contains("b", result);
        }

        [TestMethod]
        public void TryReadArrayAsSet_ShouldReturnFalse_WhenNoProperty()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "other": [] }""");

            // WHEN
            bool result = json.TryReadArrayAsSet("values", out System.Collections.Generic.HashSet<string>? set);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(set);
        }

        // ------------------------------
        // MAP READING
        // ------------------------------

        [TestMethod]
        public void ReadArrayAsMap_ShouldReturnDictionary_WhenMappingReturnsPairs()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "values": [ { "k":"x","v":"1" }, { "k":"y","v":"2"} ] }""");

            // WHEN
            System.Collections.Generic.Dictionary<string, int> result = json.ReadArrayAsMap("values", el =>
            {
                string? key = el.GetProperty("k").GetString();
                if (key is null)
                {
                    throw new NullReferenceException(nameof(key));
                }

                int val = int.Parse(el.GetProperty("v")!.GetString()!);
                return Tuple.Create(key, val);
            });

            // THEN
            Assert.HasCount(2, result);
            Assert.AreEqual(1, result["x"]);
            Assert.AreEqual(2, result["y"]);
        }

        [TestMethod]
        public void TryReadArrayAsMap_ShouldReturnFalse_WhenPropertyMissing()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "other": [] }""");

            // WHEN
            bool result = json.TryReadArrayAsMap<int, int>("values", _ => null, out System.Collections.Generic.Dictionary<int, int>? map);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(map);
        }

        [TestMethod]
        public void ReadArrayAsMap_ShouldIgnoreNullReturnedPairs()
        {
            JsonElement json = ToElement("""
        { "arr": [123, 456] }
    """);

            System.Collections.Generic.Dictionary<string, string> result = json.ReadArrayAsMap<string, string>("arr", _ => null);

            Assert.IsEmpty(result);
        }


        // ------------------------------
        // GET PROPERTY VALUE
        // ------------------------------

        [TestMethod]
        public void GetPropertyValue_String_ShouldReturnDefault_WhenMissing()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "name": "test" }""");

            // WHEN
            string value = json.GetPropertyValue("missing", "default");

            // THEN
            Assert.AreEqual("default", value);
        }

        [TestMethod]
        public void GetPropertyValue_Int_ShouldReturnStoredValue()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "value": 42 }""");

            // WHEN
            int value = json.GetPropertyValue("value", -1);

            // THEN
            Assert.AreEqual(42, value);
        }

        [TestMethod]
        public void GetPropertyEnumValue_ShouldReturnEnum()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "mode": "Friday" }""");

            // WHEN
            DayOfWeek result = json.GetPropertyEnumValue("mode", DayOfWeek.Monday);

            // THEN
            Assert.AreEqual(DayOfWeek.Friday, result);
        }

        [TestMethod]
        public void GetPropertyEnumValue_ShouldReturnDefault_WhenNotFound()
        {
            // GIVEN
            JsonElement json = ToElement("""{ "val": 10 }""");

            // WHEN
            DayOfWeek result = json.GetPropertyEnumValue("missing", DayOfWeek.Sunday);

            // THEN
            Assert.AreEqual(DayOfWeek.Sunday, result);
        }

        // ------------------------------
        // WRITE ARRAY
        // ------------------------------

        [TestMethod]
        public void WriteStringArray_ShouldSerializeStrings_AsJsonArray()
        {
            // GIVEN
            string[] input = new[] { "x", "y", "z" };
            using System.IO.MemoryStream buffer = new System.IO.MemoryStream();
            using Utf8JsonWriter writer = new Utf8JsonWriter(buffer);

            // WHEN
            writer.WriteStartObject();
            writer.WriteStringArray("values", input);
            writer.WriteEndObject();
            writer.Flush();

            JsonElement json = JsonDocument.Parse(buffer.ToArray()).RootElement;

            // THEN
            string?[] arr = json.GetProperty("values").EnumerateArray().Select(x => x.GetString()).ToArray();

            Assert.HasCount(3, arr);
            Assert.AreEqual("x", arr[0]);
            Assert.AreEqual("y", arr[1]);
            Assert.AreEqual("z", arr[2]);
        }
    }
}
