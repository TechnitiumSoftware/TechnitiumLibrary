/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;

namespace TechnitiumLibrary.Collections
{
    public class ByteTree<T>
    {
        #region variables

        protected readonly int _keySpace;
        protected readonly Node _root = new Node();

        #endregion

        #region constructor

        public ByteTree(int keySpace = 256)
        {
            _keySpace = keySpace;
        }

        #endregion

        #region public

        public void Clear()
        {
            _root.Clear();
        }

        public void Add(byte[] key, T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue != null)
                throw new ArgumentException("Key already exists.");

            node.SetValue(key, value, _keySpace);
        }

        public bool TryAdd(byte[] key, T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue != null)
                return false;

            node.SetValue(key, value, _keySpace);
            return true;
        }

        public T AddOrUpdate(byte[] key, Func<byte[], T> addValueFactory, Func<byte[], T, T> updateValueFactory)
        {
            return AddOrUpdate(key, addValueFactory(key), updateValueFactory);
        }

        public T AddOrUpdate(byte[] key, T addValue, Func<byte[], T, T> updateValueFactory)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue == null)
            {
                //key does not exists; add value
                node.SetValue(key, addValue, _keySpace);
                return addValue;
            }
            else
            {
                //key already exists; update its value
                T updateValue = updateValueFactory(key, foundValue.Value);
                node.SetValue(key, updateValue, _keySpace);
                return updateValue;
            }
        }

        public bool ContainsKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            return _root.FindClosestNode(key).GetValue(key) != null;
        }

        public bool TryGet(byte[] key, out T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue == null)
            {
                value = default;
                return false;
            }

            value = foundValue.Value;
            return true;
        }

        public T GetOrAdd(byte[] key, Func<byte[], T> valueFactory)
        {
            return GetOrAdd(key, valueFactory(key));
        }

        public T GetOrAdd(byte[] key, T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue == null)
            {
                node.SetValue(key, value, _keySpace);
                return value;
            }

            return foundValue.Value;
        }

        public bool TryRemove(byte[] key, out T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue removedValue = node.RemoveValue(key);
            if (removedValue == null)
            {
                value = default;
                return false;
            }

            node.CleanUp();

            value = removedValue.Value;
            return true;
        }

        public bool TryUpdate(byte[] key, T newValue, T comparisonValue)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = _root.FindClosestNode(key);
            NodeValue foundValue = node.GetValue(key);
            if (foundValue == null)
                return false;

            if (Equals(foundValue.Value, comparisonValue))
            {
                node.SetValue(key, newValue, _keySpace);
                return true;
            }

            return false;
        }

        #endregion

        #region properties

        public bool IsEmpty
        { get { return _root.IsEmpty; } }

        public T this[byte[] key]
        {
            get
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key));

                Node node = _root.FindClosestNode(key);
                NodeValue foundValue = node.GetValue(key);
                if (foundValue == null)
                    throw new KeyNotFoundException();

                return foundValue.Value;
            }
            set
            {
                _root.FindClosestNode(key).SetValue(key, value, _keySpace);
            }
        }

        #endregion

        protected class Node
        {
            #region variables

            readonly Node _parent;
            readonly int _depth;
            readonly byte _k;

            volatile Node[] _children;
            volatile NodeValue _value;

            #endregion

            #region constructor

            public Node()
                : this(null, 0, null)
            { }

            private Node(Node parent, byte k, NodeValue value)
            {
                if (parent == null)
                {
                    _depth = 0;
                    _k = 0;
                }
                else
                {
                    _parent = parent;
                    _depth = _parent._depth + 1;
                    _k = k;
                }

                _value = value;
            }

            #endregion

            #region private

            private static bool KeyEquals(byte[] key1, byte[] key2)
            {
                if (ReferenceEquals(key1, key2))
                    return true;

                if (key1.Length != key2.Length)
                    return false;

                for (int i = 0; i < key1.Length; i++)
                {
                    if (key1[i] != key2[i])
                        return false;
                }

                return true;
            }

            #endregion

            #region public

            public Node FindClosestNode(byte[] key)
            {
                Node current = this;

                for (int i = _depth; i < key.Length; i++)
                {
                    Node[] children = current._children;
                    if (children == null)
                        return current;

                    Node child = Volatile.Read(ref children[key[i]]);
                    if (child == null)
                        return current;

                    current = child;
                }

                return current;
            }

            public void SetValue(byte[] key, T setValue, int keySpace)
            {
                Node current = this;

                do
                {
                    if (key.Length == current._depth)
                    {
                        //key belongs to current node
                        NodeValue value = current._value;
                        if (value == null)
                        {
                            //node has no value; so set value
                            current._value = new NodeValue(key, setValue);
                            return;
                        }

                        //current node has value
                        if (value.Key.Length == current._depth)
                        {
                            //current node value belongs here; so update new value
                            value.Value = setValue;
                            return;
                        }

                        //current node value does not belong here
                        if (current._children == null)
                        {
                            //current node has no children so create new children array
                            Node[] children = new Node[keySpace];

                            //copy current value into a child
                            int k = value.Key[current._depth];
                            children[k] = new Node(current, (byte)k, value);

                            //set children array
                            current._children = children;
                        }

                        //set value here
                        current._value = new NodeValue(key, setValue);
                        return;
                    }
                    else
                    {
                        //value does not belong to current node
                        Node[] children = current._children;
                        if (children == null)
                        {
                            //current node has no children
                            NodeValue value = current._value;
                            if (value == null)
                            {
                                //current node has no children and no value so park value here for now
                                current._value = new NodeValue(key, setValue);
                                return;
                            }

                            //current node has value and no children so create new children array
                            children = new Node[keySpace];

                            if (value.Key.Length != current._depth)
                            {
                                //current value does not belong here; copy it into a child
                                int k1 = value.Key[current._depth];
                                children[k1] = new Node(current, (byte)k1, value);
                                current._value = null; //empty current value reference
                            }

                            //set children array
                            current._children = children;
                        }

                        //current node has children so set value if seat is vacant
                        int k2 = key[current._depth];
                        Node child = Volatile.Read(ref children[k2]);
                        if (child == null)
                        {
                            //set value in vacant seat and return
                            Volatile.Write(ref children[k2], new Node(current, (byte)k2, new NodeValue(key, setValue)));
                            return;
                        }

                        current = child; //make child as current and attempt to set value in next iteration
                    }
                }
                while (true);
            }

            public NodeValue GetValue(byte[] key)
            {
                Node current = this;

                do
                {
                    if (key.Length == current._depth)
                    {
                        //key belongs to current node
                        NodeValue value = current._value;
                        if (value == null)
                            return null; //no value available

                        //current node has value
                        if (value.Key.Length == current._depth)
                            return value; //current node value belongs here; return it

                        //current node value does not belong here
                        return null; //no value available
                    }

                    Node[] children = current._children;
                    if (children == null)
                    {
                        //current node has no children
                        NodeValue value = current._value;
                        if (value == null)
                            return null; //no value available

                        //check if key equals current value's key
                        if (!KeyEquals(value.Key, key))
                            return null; //keys dont match

                        return value;
                    }

                    //current node has children so check child node
                    Node child = Volatile.Read(ref children[key[current._depth]]);
                    if (child == null)
                        return null; //no value available

                    current = child; //make child as current and attempt to get value in next iteration
                }
                while (true);
            }

            public NodeValue RemoveValue(byte[] key)
            {
                Node current = this;

                do
                {
                    if (key.Length == current._depth)
                    {
                        //key belongs to current node
                        NodeValue value = current._value;
                        if (value == null)
                            return null; //no value available

                        //current node has value
                        if (value.Key.Length == current._depth)
                        {
                            //current node value belongs here; remove and return value
                            current._value = null;
                            return value;
                        }

                        //current node value does not belong here
                        return null; //no value available
                    }

                    Node[] children = current._children;
                    if (children == null)
                    {
                        //current node has no children
                        NodeValue value = current._value;
                        if (value == null)
                            return null; //no value available

                        //check if key equals current value's key
                        if (!KeyEquals(value.Key, key))
                            return null; //keys dont match

                        //remove and return value
                        current._value = null;
                        return value;
                    }

                    //current node has children so check child node
                    Node child = Volatile.Read(ref children[key[current._depth]]);
                    if (child == null)
                        return null; //no value available to remove

                    current = child; //make child as current and attempt to remove value in next iteration
                }
                while (true);
            }

            public void CleanUp()
            {
                Node current = this;

                do
                {
                    Node[] children = current._children;
                    if (children != null)
                    {
                        foreach (Node child in children)
                        {
                            if (child != null)
                                return; //current node has children; exit
                        }

                        current._children = null; //no children so cleanup
                    }

                    if (current._value != null)
                        return; //current node has value; exit

                    //current node has no children and no value
                    if (current._parent == null)
                        return; //is root

                    Node[] siblings = current._parent._children;
                    if (siblings == null)
                        return; //parent has had cleanup already; exit

                    Volatile.Write(ref siblings[current._k], null); //remove current node from parent

                    //make parent as current and proceed cleanup of parent node
                    current = current._parent;
                }
                while (true);
            }

            public void Clear()
            {
                _children = null;
                _value = null;
            }

            #endregion

            #region properties

            public Node[] Children
            { get { return _children; } }

            public NodeValue Value
            { get { return _value; } }

            public bool IsEmpty
            { get { return (_children == null) && (_value == null); } }

            #endregion
        }

        protected class NodeValue
        {
            #region variables

            readonly byte[] _key;
            T _value;

            #endregion

            #region constructor

            public NodeValue(byte[] key, T value)
            {
                _key = key;
                _value = value;
            }

            #endregion

            #region public

            public override string ToString()
            {
                return BitConverter.ToString(_key).Replace("-", "").ToLower() + ": " + _value.ToString();
            }

            #endregion

            #region properties

            public byte[] Key
            { get { return _key; } }

            public T Value
            {
                get { return _value; }
                set { _value = value; }
            }

            #endregion
        }
    }
}
