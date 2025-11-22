/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using System;
using System.Collections.Generic;
using System.Text.Json;

namespace TechnitiumLibrary
{
    public static class JsonExtensions
    {
        #region private

        private static string[] ReadArray(JsonElement jsonArray)
        {
            switch (jsonArray.ValueKind)
            {
                case JsonValueKind.Array:
                    string[] array = new string[jsonArray.GetArrayLength()];
                    int i = 0;

                    foreach (JsonElement jsonItem in jsonArray.EnumerateArray())
                        array[i++] = jsonItem.GetString();

                    return array;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        private static HashSet<string> ReadArrayAsSet(JsonElement jsonArray)
        {
            switch (jsonArray.ValueKind)
            {
                case JsonValueKind.Array:
                    HashSet<string> set = new HashSet<string>(jsonArray.GetArrayLength());

                    foreach (JsonElement jsonItem in jsonArray.EnumerateArray())
                        set.Add(jsonItem.GetString());

                    return set;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        private static T[] ReadArray<T>(JsonElement jsonArray, Func<string, T> getObject)
        {
            switch (jsonArray.ValueKind)
            {
                case JsonValueKind.Array:
                    T[] array = new T[jsonArray.GetArrayLength()];
                    int i = 0;

                    foreach (JsonElement jsonItem in jsonArray.EnumerateArray())
                        array[i++] = getObject(jsonItem.GetString());

                    return array;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        private static T[] ReadArray<T>(JsonElement jsonArray, Func<JsonElement, T> getObject)
        {
            switch (jsonArray.ValueKind)
            {
                case JsonValueKind.Array:
                    T[] array = new T[jsonArray.GetArrayLength()];
                    int i = 0;

                    foreach (JsonElement jsonItem in jsonArray.EnumerateArray())
                        array[i++] = getObject(jsonItem);

                    return array;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        private static Dictionary<TKey, TValue> ReadArrayAsMap<TKey, TValue>(JsonElement jsonArray, Func<JsonElement, Tuple<TKey, TValue>> getObject)
        {
            switch (jsonArray.ValueKind)
            {
                case JsonValueKind.Array:
                    Dictionary<TKey, TValue> map = new Dictionary<TKey, TValue>(jsonArray.GetArrayLength());

                    foreach (JsonElement jsonItem in jsonArray.EnumerateArray())
                    {
                        Tuple<TKey, TValue> item = getObject(jsonItem);
                        if (item is not null)
                            map.Add(item.Item1, item.Item2);
                    }

                    return map;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        private static Dictionary<TKey, TValue> ReadObjectAsMap<TKey, TValue>(JsonElement jsonMap, Func<string, JsonElement, Tuple<TKey, TValue>> getObject)
        {
            switch (jsonMap.ValueKind)
            {
                case JsonValueKind.Object:
                    Dictionary<TKey, TValue> map = new Dictionary<TKey, TValue>();

                    foreach (JsonProperty jsonProperty in jsonMap.EnumerateObject())
                    {
                        Tuple<TKey, TValue> item = getObject(jsonProperty.Name, jsonProperty.Value);
                        if (item is not null)
                            map.Add(item.Item1, item.Item2);
                    }

                    return map;

                case JsonValueKind.Null:
                    return null;

                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region public

        public static string[] GetArray(this JsonElement jsonElement)
        {
            return ReadArray(jsonElement);
        }

        public static string[] ReadArray(this JsonElement jsonElement, string propertyName)
        {
            return ReadArray(jsonElement.GetProperty(propertyName));
        }

        public static bool TryReadArray(this JsonElement jsonElement, string propertyName, out string[] array)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                array = ReadArray(jsonArray);
                return true;
            }

            array = null;
            return false;
        }

        public static T[] ReadArray<T>(this JsonElement jsonElement, string propertyName, Func<string, T> getObject)
        {
            return ReadArray(jsonElement.GetProperty(propertyName), getObject);
        }

        public static bool TryReadArray<T>(this JsonElement jsonElement, string propertyName, Func<string, T> getObject, out T[] array)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                array = ReadArray(jsonArray, getObject);
                return true;
            }

            array = null;
            return false;
        }

        public static T[] ReadArray<T>(this JsonElement jsonElement, string propertyName, Func<JsonElement, T> getObject)
        {
            return ReadArray(jsonElement.GetProperty(propertyName), getObject);
        }

        public static bool TryReadArray<T>(this JsonElement jsonElement, string propertyName, Func<JsonElement, T> getObject, out T[] array)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                array = ReadArray(jsonArray, getObject);
                return true;
            }

            array = null;
            return false;
        }

        public static HashSet<string> ReadArrayAsSet(this JsonElement jsonElement, string propertyName)
        {
            return ReadArrayAsSet(jsonElement.GetProperty(propertyName));
        }

        public static bool TryReadArrayAsSet(this JsonElement jsonElement, string propertyName, out HashSet<string> set)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                set = ReadArrayAsSet(jsonArray);
                return true;
            }

            set = null;
            return false;
        }

        public static Dictionary<TKey, TValue> ReadArrayAsMap<TKey, TValue>(this JsonElement jsonElement, string propertyName, Func<JsonElement, Tuple<TKey, TValue>> getObject)
        {
            return ReadArrayAsMap(jsonElement.GetProperty(propertyName), getObject);
        }

        public static bool TryReadArrayAsMap<TKey, TValue>(this JsonElement jsonElement, string propertyName, Func<JsonElement, Tuple<TKey, TValue>> getObject, out Dictionary<TKey, TValue> map)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                map = ReadArrayAsMap(jsonArray, getObject);
                return true;
            }

            map = null;
            return false;
        }

        public static Dictionary<TKey, TValue> ReadObjectAsMap<TKey, TValue>(this JsonElement jsonElement, string propertyName, Func<string, JsonElement, Tuple<TKey, TValue>> getObject)
        {
            JsonElement jsonMap = jsonElement.GetProperty(propertyName);
            Dictionary<TKey, TValue> map = new Dictionary<TKey, TValue>();

            foreach (JsonProperty jsonProperty in jsonMap.EnumerateObject())
            {
                Tuple<TKey, TValue> item = getObject(jsonProperty.Name, jsonProperty.Value);
                if (item is not null)
                    map.Add(item.Item1, item.Item2);
            }

            return map;
        }

        public static bool TryReadObjectAsMap<TKey, TValue>(this JsonElement jsonElement, string propertyName, Func<string, JsonElement, Tuple<TKey, TValue>> getObject, out Dictionary<TKey, TValue> map)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonArray))
            {
                map = ReadObjectAsMap(jsonArray, getObject);
                return true;
            }

            map = null;
            return false;
        }

        public static string GetPropertyValue(this JsonElement jsonElement, string propertyName, string defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return jsonValue.GetString();

            return defaultValue;
        }

        public static bool GetPropertyValue(this JsonElement jsonElement, string propertyName, bool defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return jsonValue.GetBoolean();

            return defaultValue;
        }

        public static int GetPropertyValue(this JsonElement jsonElement, string propertyName, int defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return jsonValue.GetInt32();

            return defaultValue;
        }

        public static uint GetPropertyValue(this JsonElement jsonElement, string propertyName, uint defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return jsonValue.GetUInt32();

            return defaultValue;
        }

        public static long GetPropertyValue(this JsonElement jsonElement, string propertyName, long defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return jsonValue.GetInt64();

            return defaultValue;
        }

        public static T GetPropertyValue<T>(this JsonElement jsonElement, string propertyName, Func<string, T> parse, T defaultValue)
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue) && (jsonValue.ValueKind == JsonValueKind.String))
                return parse(jsonValue.GetString());

            return defaultValue;
        }

        public static T GetPropertyEnumValue<T>(this JsonElement jsonElement, string propertyName, T defaultValue) where T : struct
        {
            if (jsonElement.TryGetProperty(propertyName, out JsonElement jsonValue))
                return Enum.Parse<T>(jsonValue.GetString(), true);

            return defaultValue;
        }

        public static void WriteStringArray<T>(this Utf8JsonWriter jsonWriter, string propertyName, IReadOnlyCollection<T> values)
        {
            jsonWriter.WritePropertyName(propertyName);
            jsonWriter.WriteStartArray();

            if (values is not null)
            {
                foreach (T value in values)
                    jsonWriter.WriteStringValue(value.ToString());
            }

            jsonWriter.WriteEndArray();
        }

        #endregion
    }
}
