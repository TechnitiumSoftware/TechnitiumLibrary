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
using System.Collections;
using System.Collections.Generic;
using System.Threading;

namespace TechnitiumLibrary.ByteTree
{
    public class ByteTree<TValue> : ByteTree<byte[], TValue> where TValue : class
    {
        public ByteTree()
            : base(256)
        { }

        protected override byte[] ConvertToByteKey(byte[] key)
        {
            return key;
        }
    }

    public abstract class ByteTree<TKey, TValue> : IEnumerable<TValue> where TValue : class
    {
        #region variables

        protected readonly int _keySpace;
        protected readonly Node _root = new Node();

        #endregion

        #region constructor

        protected ByteTree(int keySpace)
        {
            if ((keySpace < 0) || (keySpace > 256))
                throw new ArgumentOutOfRangeException(nameof(keySpace));

            _keySpace = keySpace;
        }

        #endregion

        #region protected

        protected abstract byte[] ConvertToByteKey(TKey key);

        #endregion

        #region public

        public void Clear()
        {
            _root.Clear();
        }

        public void Add(TKey key, TValue value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (!_root.AddValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _))
                throw new ArgumentException("Key already exists.");
        }

        public bool TryAdd(TKey key, TValue value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            return _root.AddValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _);
        }

        public TValue AddOrUpdate(TKey key, Func<TKey, TValue> addValueFactory, Func<TKey, TValue, TValue> updateValueFactory)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            TValue addValue = addValueFactory(key);

            if (_root.AddValue(bKey, delegate () { return new NodeValue(bKey, addValue); }, _keySpace, out NodeValue existingValue))
                return addValue;

            TValue updateValue = updateValueFactory(key, existingValue.Value);
            existingValue.Value = updateValue;
            return updateValue;
        }

        public TValue AddOrUpdate(TKey key, TValue addValue, Func<TKey, TValue, TValue> updateValueFactory)
        {
            return AddOrUpdate(key, delegate (TKey k) { return addValue; }, updateValueFactory);
        }

        public bool ContainsKey(TKey key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            return _root.FindNodeValue(bKey, out _) != null;
        }

        public bool TryGet(TKey key, out TValue value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out _);
            if (nodeValue == null)
            {
                value = default;
                return false;
            }

            value = nodeValue.Value;
            return true;
        }

        public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            TValue value = valueFactory(key);
            if (_root.AddValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out NodeValue existingValue))
                return value;

            return existingValue.Value;
        }

        public TValue GetOrAdd(TKey key, TValue value)
        {
            return GetOrAdd(key, delegate (TKey k) { return value; });
        }

        public bool TryRemove(TKey key, out TValue value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue removedValue = _root.RemoveValue(bKey, out Node closestNode);
            if (removedValue == null)
            {
                value = default;
                return false;
            }

            value = removedValue.Value;

            closestNode.CleanUp();

            return true;
        }

        public bool TryUpdate(TKey key, TValue newValue, TValue comparisonValue)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out _);
            if (nodeValue == null)
                return false;

            return nodeValue.TryUpdateValue(newValue, comparisonValue);
        }

        public IEnumerator<TValue> GetEnumerator()
        {
            return new ByteTreeEnumerator(_root);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new ByteTreeEnumerator(_root);
        }

        #endregion

        #region properties

        public bool IsEmpty
        { get { return _root.IsEmpty; } }

        public TValue this[TKey key]
        {
            get
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key));

                byte[] bKey = ConvertToByteKey(key);

                NodeValue nodeValue = _root.FindNodeValue(bKey, out _);
                if (nodeValue == null)
                    throw new KeyNotFoundException();

                return nodeValue.Value;
            }
            set
            {
                AddOrUpdate(key, delegate (TKey k) { return value; }, delegate (TKey k, TValue v) { return value; });
            }
        }

        #endregion

        protected sealed class Node
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

            private static bool KeyEquals(int startIndex, byte[] key1, byte[] key2)
            {
                if (key1.Length != key2.Length)
                    return false;

                for (int i = startIndex; i < key1.Length; i++)
                {
                    if (key1[i] != key2[i])
                        return false;
                }

                return true;
            }

            #endregion

            #region public

            public bool AddValue(byte[] key, Func<NodeValue> newValue, int keySpace, out NodeValue existingValue)
            {
                Node current = this;

                while (current._depth < key.Length)
                {
                    Node[] children = current._children;
                    if (children == null)
                    {
                        //current node has no children
                        NodeValue value = current._value;
                        if (value == null)
                        {
                            //current node has no children and no value so add value here
                            NodeValue originalValue = Interlocked.CompareExchange(ref current._value, newValue(), null);
                            if (originalValue is null)
                            {
                                existingValue = null;
                                return true;
                            }

                            //seems another thread already set its value here; use that reference
                            value = originalValue;
                        }

                        if (KeyEquals(current._depth, value.Key, key))
                        {
                            //current value key equals to add value key
                            existingValue = value;
                            return false; //failed to add new value as value already exists
                        }

                        //current node has value and no children so create new children array
                        children = new Node[keySpace];

                        if (value.Key.Length != current._depth)
                        {
                            //current value does not belong here; copy it into a new child node
                            int k1 = value.Key[current._depth];
                            children[k1] = new Node(current, (byte)k1, value);
                        }

                        //set children array
                        Node[] originalChildren = Interlocked.CompareExchange(ref current._children, children, null);
                        if (originalChildren is null)
                        {
                            //current thread successfully set children so it has right to update current value
                            if (value.Key.Length != current._depth)
                            {
                                //remove current value reference since it does not belong here and was successfully copied to child node
                                current._value = null;
                            }
                        }
                        else
                        {
                            //another thread already added children; use that reference
                            children = originalChildren;
                        }
                    }

                    //current node has children so set value if seat is vacant
                    int k2 = key[current._depth];
                    Node child = Volatile.Read(ref children[k2]);
                    if (child == null)
                    {
                        //set value in vacant seat and return
                        Node originalChild = Interlocked.CompareExchange(ref children[k2], new Node(current, (byte)k2, newValue()), null);
                        if (originalChild is null)
                        {
                            existingValue = null;
                            return true;
                        }

                        //another thread already added child; use that reference
                        child = originalChild;
                    }

                    current = child;
                }

                //key belongs to current
                do
                {
                    NodeValue value = current._value;
                    if (value == null)
                    {
                        //node has no value; so add value here
                        NodeValue originalValue = Interlocked.CompareExchange(ref current._value, newValue(), null);
                        if (originalValue is null)
                        {
                            existingValue = null;
                            return true;
                        }

                        //seems another thread already set its value here; use that reference
                        value = originalValue;
                    }

                    //current node has value
                    if (value.Key.Length == current._depth)
                    {
                        //current node has value and it belongs here
                        existingValue = value;
                        return false; //failed to add new value as value already exists
                    }

                    //current node has value that does not belong here
                    if (current._children == null)
                    {
                        //current node has no children so create new children array
                        Node[] children = new Node[keySpace];

                        //copy current value into a child node
                        int k = value.Key[current._depth];
                        children[k] = new Node(current, (byte)k, value);

                        //set children array
                        Node[] originalChildren = Interlocked.CompareExchange(ref current._children, children, null);
                        if (originalChildren is null)
                        {
                            //current thread successfully added children; wins rights to add value here
                            //add value here by overwriting current value that does not belong here and was moved to child node
                            current._value = newValue();
                            existingValue = null;
                            return true;
                        }
                    }

                    //current node has children and current value does not belong here
                    //this means another thread has already set children and will set current value to proper value or null
                    //wait in this loop till value is set by that another thread
                }
                while (true);
            }

            public NodeValue FindNodeValue(byte[] key, out Node closestNode)
            {
                closestNode = this;

                while (closestNode._depth < key.Length)
                {
                    Node[] children = closestNode._children;
                    if (children == null)
                        break;

                    Node child = Volatile.Read(ref children[key[closestNode._depth]]);
                    if (child == null)
                        return null; //value not found

                    closestNode = child;
                }

                //either closestNode is leaf or key belongs to closestNode
                NodeValue value = closestNode._value;

                if ((value != null) && KeyEquals(closestNode._depth, value.Key, key))
                    return value; //value found

                return null; //value key does not match
            }

            public NodeValue RemoveValue(byte[] key, out Node closestNode)
            {
                closestNode = this;

                while (closestNode._depth < key.Length)
                {
                    Node[] children = closestNode._children;
                    if (children == null)
                        break;

                    Node child = Volatile.Read(ref children[key[closestNode._depth]]);
                    if (child == null)
                        return null; //value not found

                    closestNode = child;
                }

                //either closestNode is leaf or key belongs to closestNode
                NodeValue value = closestNode._value;

                if ((value != null) && KeyEquals(closestNode._depth, value.Key, key))
                {
                    //value found; remove and return value
                    closestNode._value = null;
                    return value;
                }

                return null; //value key does not match
            }

            public void CleanUp()
            {
                Node current = this;

                do
                {
                    Node[] children = current._children;
                    if (children != null)
                    {
                        for (int i = 0; i < children.Length; i++)
                        {
                            if (Volatile.Read(ref children[i]) != null)
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

                    //remove current node from parent
                    Volatile.Write(ref siblings[current._k], null);

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

            public Node GetNextNodeWithValue(int baseDepth)
            {
                int k = 0;
                Node current = this;

                while ((current != null) && (current._depth >= baseDepth))
                {
                    Node[] children = current._children;
                    if (children != null)
                    {
                        //find child node
                        Node child = null;

                        for (int i = k; i < children.Length; i++)
                        {
                            child = Volatile.Read(ref children[i]);
                            if (child != null)
                            {
                                if (child._value != null)
                                    return child; //child has value so return it

                                if (child._children != null)
                                    break;
                            }
                        }

                        if (child != null)
                        {
                            //make found child as current
                            k = 0;
                            current = child;
                            continue; //start over
                        }
                    }

                    //no child nodes available; move up to parent node
                    k = current._k + 1;
                    current = current._parent;
                }

                return null;
            }

            #endregion

            #region properties

            public Node Parent
            { get { return _parent; } }

            public int Depth
            { get { return _depth; } }

            public byte K
            { get { return _k; } }

            public Node[] Children
            { get { return _children; } }

            public NodeValue Value
            { get { return _value; } }

            public bool IsEmpty
            { get { return (_children == null) && (_value == null); } }

            #endregion
        }

        protected sealed class NodeValue
        {
            #region variables

            readonly byte[] _key;
            TValue _value;

            #endregion

            #region constructor

            public NodeValue(byte[] key, TValue value)
            {
                _key = key;
                _value = value;
            }

            #endregion

            #region public

            public bool TryUpdateValue(TValue newValue, TValue comparisonValue)
            {
                TValue originalValue = Interlocked.CompareExchange(ref _value, newValue, comparisonValue);
                return ReferenceEquals(originalValue, comparisonValue);
            }

            public override string ToString()
            {
                return BitConverter.ToString(_key).Replace("-", "").ToLower() + ": " + _value.ToString();
            }

            #endregion

            #region properties

            public byte[] Key
            { get { return _key; } }

            public TValue Value
            {
                get { return _value; }
                set { _value = value; }
            }

            #endregion
        }

        protected sealed class ByteTreeEnumerator : IEnumerator<TValue>
        {
            #region variables

            readonly Node _root;

            Node _current;
            NodeValue _value;
            bool _finished;

            #endregion

            #region constructor

            public ByteTreeEnumerator(Node root)
            {
                _root = root;
            }

            #endregion

            #region public

            public void Dispose()
            {
                //do nothing
            }

            public TValue Current
            {
                get
                {
                    if (_value == null)
                        return default;

                    return _value.Value;
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    if (_value == null)
                        return default;

                    return _value.Value;
                }
            }

            public void Reset()
            {
                _current = null;
                _value = null;
                _finished = false;
            }

            public bool MoveNext()
            {
                if (_finished)
                    return false;

                if (_current == null)
                {
                    _current = _root;

                    NodeValue value = _current.Value;
                    if (value != null)
                    {
                        _value = value;
                        return true;
                    }
                }

                do
                {
                    _current = _current.GetNextNodeWithValue(_root.Depth);
                    if (_current == null)
                    {
                        _value = null;
                        _finished = true;
                        return false;
                    }

                    NodeValue value = _current.Value;
                    if (value != null)
                    {
                        _value = value;
                        return true;
                    }
                }
                while (true);
            }

            #endregion
        }
    }
}
