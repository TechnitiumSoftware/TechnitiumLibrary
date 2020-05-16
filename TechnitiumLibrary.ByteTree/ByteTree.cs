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
    public class ByteTree<T> : IEnumerable<T>
    {
        #region variables

        protected readonly int _keySpace;
        protected readonly Node _root = new Node();

        #endregion

        #region constructor

        public ByteTree(int keySpace = 256)
        {
            if ((keySpace < 0) || (keySpace > 256))
                throw new ArgumentOutOfRangeException(nameof(keySpace));

            _keySpace = keySpace;
        }

        #endregion

        #region protected

        protected Node FindClosestNode(byte[] key)
        {
            Node[] children;
            Node child;
            Node current = _root;

            for (int i = 0; i < key.Length; i++)
            {
                children = current._children;
                if (children == null)
                    break;

                child = Volatile.Read(ref children[key[i]]);
                if (child == null)
                    break;

                current = child;
            }

            return current;
        }

        protected NodeValue FindValue(byte[] key, out Node closestNode)
        {
            Node[] children;
            Node child;

            closestNode = _root;

            for (int i = 0; i < key.Length; i++)
            {
                children = closestNode._children;
                if (children == null)
                    break;

                child = Volatile.Read(ref children[key[i]]);
                if (child == null)
                    return null; //no value available

                closestNode = child;
            }

            return closestNode.GetValue(key);
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

            NodeValue foundValue = FindValue(key, out Node closestNode);
            if (foundValue != null)
                throw new ArgumentException("Key already exists.");

            closestNode.SetValue(key, value, _keySpace);
        }

        public bool TryAdd(byte[] key, T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            NodeValue foundValue = FindValue(key, out Node closestNode);
            if (foundValue != null)
                return false;

            closestNode.SetValue(key, value, _keySpace);
            return true;
        }

        public T AddOrUpdate(byte[] key, Func<byte[], T> addValueFactory, Func<byte[], T, T> updateValueFactory)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            NodeValue foundValue = FindValue(key, out Node closestNode);
            if (foundValue == null)
            {
                //key does not exists; add value
                T addValue = addValueFactory(key);
                closestNode.SetValue(key, addValue, _keySpace);
                return addValue;
            }
            else
            {
                //key already exists; update its value
                T updateValue = updateValueFactory(key, foundValue._value);
                closestNode.SetValue(key, updateValue, _keySpace);
                return updateValue;
            }
        }

        public T AddOrUpdate(byte[] key, T addValue, Func<byte[], T, T> updateValueFactory)
        {
            return AddOrUpdate(key, delegate (byte[] k) { return addValue; }, updateValueFactory);
        }

        public bool ContainsKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            return FindValue(key, out _) != null;
        }

        public bool TryGet(byte[] key, out T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            NodeValue foundValue = FindValue(key, out _);
            if (foundValue == null)
            {
                value = default;
                return false;
            }

            value = foundValue._value;
            return true;
        }

        public T GetOrAdd(byte[] key, Func<byte[], T> valueFactory)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            NodeValue foundValue = FindValue(key, out Node closestNode);
            if (foundValue == null)
            {
                T value = valueFactory(key);
                closestNode.SetValue(key, value, _keySpace);
                return value;
            }

            return foundValue._value;
        }

        public T GetOrAdd(byte[] key, T value)
        {
            return GetOrAdd(key, delegate (byte[] k) { return value; });
        }

        public bool TryRemove(byte[] key, out T value)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Node node = FindClosestNode(key);
            NodeValue removedValue = node.RemoveValue(key);
            if (removedValue == null)
            {
                value = default;
                return false;
            }

            node.CleanUp();

            value = removedValue._value;
            return true;
        }

        public bool TryUpdate(byte[] key, T newValue, T comparisonValue)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            NodeValue foundValue = FindValue(key, out Node closestNode);
            if (foundValue == null)
                return false;

            if (Equals(foundValue._value, comparisonValue))
            {
                closestNode.SetValue(key, newValue, _keySpace);
                return true;
            }

            return false;
        }

        public IEnumerator<T> GetEnumerator()
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

        public T this[byte[] key]
        {
            get
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key));

                NodeValue foundValue = FindValue(key, out _);
                if (foundValue == null)
                    throw new KeyNotFoundException();

                return foundValue._value;
            }
            set
            {
                FindClosestNode(key).SetValue(key, value, _keySpace);
            }
        }

        #endregion

        protected sealed class Node
        {
            #region variables

            public readonly Node _parent;
            public readonly int _depth;
            public readonly byte _k;

            public volatile Node[] _children;
            public volatile NodeValue _value;

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
                        if (value._key.Length == current._depth)
                        {
                            //current node value belongs here; so update new value
                            value._value = setValue;
                            return;
                        }

                        //current node value does not belong here
                        if (current._children == null)
                        {
                            //current node has no children so create new children array
                            Node[] children = new Node[keySpace];

                            //copy current value into a child
                            int k = value._key[current._depth];
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

                            if (value._key.Length != current._depth)
                            {
                                //current value does not belong here; copy it into a child
                                int k1 = value._key[current._depth];
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
                        if (value._key.Length == current._depth)
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
                        if (KeyEquals(current._depth, value._key, key))
                            return value; //keys match; return it

                        return null; //keys dont match
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
                        if (value._key.Length == current._depth)
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
                        if (KeyEquals(current._depth, value._key, key))
                        {
                            //keys match; remove and return value
                            current._value = null;
                            return value;
                        }

                        return null; //keys dont match
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
                Node[] children;
                Node[] siblings;

                do
                {
                    children = current._children;
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

                    siblings = current._parent._children;
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

            public Node GetNextValueNode(int baseDepth)
            {
                int k = 0;
                Node current = this;
                Node[] children;
                Node child;

                while ((current != null) && (current._depth >= baseDepth))
                {
                    children = current._children;
                    if (children != null)
                    {
                        //find child node
                        child = null;

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

            public bool IsEmpty
            { get { return (_children == null) && (_value == null); } }

            #endregion
        }

        protected sealed class NodeValue
        {
            #region variables

            public readonly byte[] _key;
            public T _value;

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
        }

        protected sealed class ByteTreeEnumerator : IEnumerator<T>
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

            public T Current
            {
                get
                {
                    if (_value == null)
                        return default;

                    return _value._value;
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    if (_value == null)
                        return default;

                    return _value._value;
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

                NodeValue value;

                if (_current == null)
                {
                    _current = _root;

                    value = _current._value;
                    if (value != null)
                    {
                        _value = value;
                        return true;
                    }
                }

                do
                {
                    _current = _current.GetNextValueNode(_root._depth);
                    if (_current == null)
                    {
                        _value = null;
                        _finished = true;
                        return false;
                    }

                    value = _current._value;
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
