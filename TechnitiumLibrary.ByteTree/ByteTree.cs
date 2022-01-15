/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
        public ByteTree(int keySpace = 256)
            : base(keySpace)
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
        protected readonly Node _root;

        #endregion

        #region constructor

        protected ByteTree(int keySpace)
        {
            if ((keySpace < 0) || (keySpace > 256))
                throw new ArgumentOutOfRangeException(nameof(keySpace));

            _keySpace = keySpace;
            _root = new Node(null, 0, _keySpace, null);
        }

        #endregion

        #region protected

        protected abstract byte[] ConvertToByteKey(TKey key);

        protected bool TryRemove(TKey key, out TValue value, out Node closestNode)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue removedValue = _root.RemoveNodeValue(bKey, out closestNode);
            if (removedValue is null)
            {
                value = default;
                return false;
            }

            //by default TryRemove wont call closestNode.CleanThisBranch() so that operations are atomic but will use up memory since stem nodes wont be cleaned up
            //override the public method if the implementation requires to save memory and take a chance of remove operation deleting an added NodeValue due to race condition

            value = removedValue.Value;
            return true;
        }

        protected bool TryGet(TKey key, out TValue value, out Node closestNode)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out closestNode);
            if (nodeValue is null)
            {
                value = default;
                return false;
            }

            value = nodeValue.Value;
            return true;
        }

        #endregion

        #region public

        public void Clear()
        {
            _root.ClearNode();
        }

        public void Add(TKey key, TValue value)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (!_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _, out _))
                throw new ArgumentException("Key already exists.");
        }

        public bool TryAdd(TKey key, TValue value)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            return _root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, value); }, _keySpace, out _, out _);
        }

        public TValue AddOrUpdate(TKey key, Func<TKey, TValue> addValueFactory, Func<TKey, TValue, TValue> updateValueFactory)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, addValueFactory(key)); }, _keySpace, out NodeValue addedValue, out NodeValue existingValue))
                return addedValue.Value;

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
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            return _root.FindNodeValue(bKey, out _) is not null;
        }

        public bool TryGet(TKey key, out TValue value)
        {
            return TryGet(key, out value, out _);
        }

        public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            if (_root.AddNodeValue(bKey, delegate () { return new NodeValue(bKey, valueFactory(key)); }, _keySpace, out NodeValue addedValue, out NodeValue existingValue))
                return addedValue.Value;

            return existingValue.Value;
        }

        public TValue GetOrAdd(TKey key, TValue value)
        {
            return GetOrAdd(key, delegate (TKey k) { return value; });
        }

        public virtual bool TryRemove(TKey key, out TValue value)
        {
            return TryRemove(key, out value, out _);
        }

        public bool TryUpdate(TKey key, TValue newValue, TValue comparisonValue)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            byte[] bKey = ConvertToByteKey(key);

            NodeValue nodeValue = _root.FindNodeValue(bKey, out _);
            if (nodeValue is null)
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
                if (key is null)
                    throw new ArgumentNullException(nameof(key));

                byte[] bKey = ConvertToByteKey(key);

                NodeValue nodeValue = _root.FindNodeValue(bKey, out _);
                if (nodeValue is null)
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

            readonly Node[] _children;
            volatile NodeValue _value;

            #endregion

            #region constructor

            public Node(Node parent, byte k, int keySpace, NodeValue value)
            {
                if (parent is null)
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

                if (keySpace > 0)
                    _children = new Node[keySpace];

                _value = value;

                if ((_children is null) && (_value is null))
                    throw new InvalidOperationException();
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

            public bool AddNodeValue(byte[] key, Func<NodeValue> newValue, int keySpace, out NodeValue addedValue, out NodeValue existingValue)
            {
                Node current = this;

                do //try again loop
                {
                    while (current._depth < key.Length) //find loop
                    {
                        if (current._children is null)
                            break;

                        byte k = key[current._depth];
                        Node child = Volatile.Read(ref current._children[k]);
                        if (child is null)
                        {
                            //try set new leaf node with add value in this empty spot
                            Node addNewNode = new Node(current, k, 0, newValue());
                            Node originalChild = Interlocked.CompareExchange(ref current._children[k], addNewNode, null);
                            if (originalChild is null)
                            {
                                //value added as leaf node
                                addedValue = addNewNode._value;
                                existingValue = null;
                                return true;
                            }

                            //another thread already added a child; use that reference
                            child = originalChild;
                        }

                        current = child;
                    }

                    //either current is leaf or key belongs to current
                    NodeValue value = current._value;

                    if ((value is not null) && KeyEquals(current._depth, value.Key, key))
                    {
                        //value found; cannot add
                        addedValue = null;
                        existingValue = value;
                        return false;
                    }
                    else
                    {
                        //value key does not match
                        if (current._children is null)
                        {
                            //current node is a leaf (has no children); convert it into stem node
                            Node stemNode;

                            if (value.Key.Length == current._depth)
                            {
                                //current value belongs current leaf node
                                //replace current leaf node with a stem node with current value
                                stemNode = new Node(current._parent, current._k, keySpace, value);
                            }
                            else
                            {
                                //current value does not belong to current leaf node
                                //replace current leaf node with a stem node with null value
                                stemNode = new Node(current._parent, current._k, keySpace, null);

                                //copy current value into a child leaf node
                                byte k = value.Key[current._depth];
                                stemNode._children[k] = new Node(stemNode, k, 0, value);
                            }

                            //replace stem node in parent
                            Node originalNode = Interlocked.CompareExchange(ref current._parent._children[current._k], stemNode, current);
                            if (ReferenceEquals(originalNode, current))
                            {
                                //successfully added stem node
                                //use new stem node as current node and try again
                                current = stemNode;
                            }
                            else
                            {
                                //another thread already placed new stem node or removed it
                                if (originalNode is null)
                                {
                                    //stem node was removed by another thread; start over again
                                    current = this;
                                }
                                else
                                {
                                    //use new stem node reference as current and try again
                                    current = originalNode;
                                }
                            }
                        }
                        else
                        {
                            //current node is stem with no/invalid value; add value here
                            NodeValue addNewValue = newValue();
                            NodeValue originalValue = Interlocked.CompareExchange(ref current._value, addNewValue, value);
                            if (ReferenceEquals(originalValue, value))
                            {
                                //value added successfully
                                addedValue = addNewValue;
                                existingValue = null;
                                return true;
                            }

                            if (originalValue is not null)
                            {
                                //another thread added value to stem node; return its reference
                                addedValue = null;
                                existingValue = originalValue;
                                return false;
                            }

                            //another thread removed value; try again
                        }
                    }
                }
                while (true);
            }

            public NodeValue FindNodeValue(byte[] key, out Node closestNode)
            {
                closestNode = this;

                while (closestNode._depth < key.Length) //find loop
                {
                    if (closestNode._children is null)
                        break;

                    Node child = Volatile.Read(ref closestNode._children[key[closestNode._depth]]);
                    if (child is null)
                        return null; //value not found

                    closestNode = child;
                }

                //either closestNode is leaf or key belongs to closestNode
                NodeValue value = closestNode._value;

                if ((value is not null) && KeyEquals(closestNode._depth, value.Key, key))
                    return value; //value found

                return null; //value key does not match
            }

            public NodeValue RemoveNodeValue(byte[] key, out Node closestNode)
            {
                closestNode = this;

                do //try again loop
                {
                    while (closestNode._depth < key.Length) //find loop
                    {
                        if (closestNode._children is null)
                            break;

                        Node child = Volatile.Read(ref closestNode._children[key[closestNode._depth]]);
                        if (child is null)
                            return null; //value not found

                        closestNode = child;
                    }

                    //either closestNode is leaf or key belongs to closestNode
                    NodeValue value = closestNode._value;

                    if ((value is not null) && KeyEquals(closestNode._depth, value.Key, key))
                    {
                        //value found; remove and return value
                        if (closestNode._children is null)
                        {
                            //remove leaf node directly from parent
                            Node originalNode = Interlocked.CompareExchange(ref closestNode._parent._children[closestNode._k], null, closestNode);
                            if (ReferenceEquals(originalNode, closestNode))
                                return value; //leaf node removed successfully

                            if (originalNode is null)
                            {
                                //another thread removed leaf node
                                return null;
                            }
                            else
                            {
                                //another thread replaced leaf node with stem node; use new reference and try again in next iteration
                                closestNode = originalNode;
                            }
                        }
                        else
                        {
                            //remove value from stem node
                            NodeValue originalValue = Interlocked.CompareExchange(ref closestNode._value, null, value);
                            if (ReferenceEquals(originalValue, value))
                                return value; //successfully removed stem node value

                            //another thread removed stem node value
                            return null;
                        }
                    }
                    else
                    {
                        //value key does not match
                        return null;
                    }
                }
                while (true);
            }

            public void CleanThisBranch()
            {
                Node current = this;

                while (current._parent is not null)
                {
                    if (current._children is null)
                    {
                        //current node is leaf
                        //leaf node already was removed so move up to parent
                    }
                    else
                    {
                        //current node is stem
                        if (!current.IsEmpty)
                            return;

                        //remove current node from parent
                        Volatile.Write(ref current._parent._children[current._k], null);
                    }

                    //make parent as current and proceed cleanup of parent node
                    current = current._parent;
                }
            }

            public void ClearNode()
            {
                //remove value
                _value = null;

                if (_children is not null)
                {
                    //remove all children
                    for (int i = 0; i < _children.Length; i++)
                        Volatile.Write(ref _children[i], null);
                }
            }

            public Node GetNextNodeWithValue(int baseDepth)
            {
                int k = 0;
                Node current = this;

                while ((current is not null) && (current._depth >= baseDepth))
                {
                    if (current._children is not null)
                    {
                        //find child node
                        Node child = null;

                        for (int i = k; i < current._children.Length; i++)
                        {
                            child = Volatile.Read(ref current._children[i]);
                            if (child is not null)
                            {
                                if (child._value is not null)
                                    return child; //child has value so return it

                                if (child._children is not null)
                                    break;
                            }
                        }

                        if (child is not null)
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
            {
                get
                {
                    if (_value is not null)
                        return false;

                    if (_children is not null)
                    {
                        for (int i = 0; i < _children.Length; i++)
                        {
                            if (Volatile.Read(ref _children[i]) is not null)
                                return false;
                        }
                    }

                    return true;
                }
            }

            public bool HasChildren
            {
                get
                {
                    if (_children is null)
                        return false;

                    for (int i = 0; i < _children.Length; i++)
                    {
                        if (Volatile.Read(ref _children[i]) is not null)
                            return true;
                    }

                    return false;
                }
            }

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
                return Convert.ToHexString(_key).ToLower() + ": " + _value.ToString();
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
                    if (_value is null)
                        return default;

                    return _value.Value;
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    if (_value is null)
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

                if (_current is null)
                {
                    _current = _root;

                    NodeValue value = _current.Value;
                    if (value is not null)
                    {
                        _value = value;
                        return true;
                    }
                }

                do
                {
                    _current = _current.GetNextNodeWithValue(_root.Depth);
                    if (_current is null)
                    {
                        _value = null;
                        _finished = true;
                        return false;
                    }

                    NodeValue value = _current.Value;
                    if (value is not null)
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
