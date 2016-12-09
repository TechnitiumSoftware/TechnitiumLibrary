/*
Technitium Library
Copyright (C) 2016  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.BTree
{
    public class BTreeNode<T> : IEnumerable<BTreeNodeValue<T>>
    {
        #region variables

        BTreeNode<T> _parentNode;
        int _depth;
        byte _k;
        BTreeNode<T>[] _childNodes;

        BTreeNodeValue<T> _holdValue;
        BTreeNodeValue<T> _nodeValue;

        #endregion

        #region constructor

        public BTreeNode(BTreeNode<T> parentNode, byte k)
        {
            if (parentNode == null)
            {
                _depth = 0;
                _k = 0;
            }
            else
            {
                _parentNode = parentNode;
                _depth = _parentNode._depth + 1;
                _k = k;
            }
        }

        #endregion

        #region private

        private BTreeNode<T> FindClosestNode(byte[] key)
        {
            BTreeNode<T> currentNode = this;

            for (int i = this._depth; i < key.Length; i++)
            {
                if (currentNode._childNodes == null)
                    return currentNode;

                int k = key[i];
                BTreeNode<T> childNode = currentNode._childNodes[k];

                if (childNode == null)
                    return currentNode;

                currentNode = childNode;
            }

            return currentNode;
        }

        private BTreeNode<T> GetLastNode()
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                BTreeNode<T>[] childNodes = currentNode._childNodes;

                if (childNodes == null)
                    return currentNode; //current node is last node

                //find last child of current node
                BTreeNode<T> lastChildNode = null;

                for (int k = 255; k > -1; k--)
                {
                    if (childNodes[k] != null)
                    {
                        lastChildNode = childNodes[k];
                        break;
                    }
                }

                if (lastChildNode == null)
                    return currentNode; //current node doesnt have any child nodes so its last node

                currentNode = lastChildNode;
            }
        }

        private BTreeNode<T> GetNextNode()
        {
            if (_childNodes != null)
            {
                //return first child node
                foreach (BTreeNode<T> childNode in _childNodes)
                {
                    if (childNode != null)
                        return childNode;
                }
            }

            //no child nodes available, move up to parent node & find next sibling node
            BTreeNode<T> currentNode = this;

            while (true)
            {
                BTreeNode<T> parentNode = currentNode._parentNode;

                if (parentNode == null)
                    return null; //current node is root node

                //find next sibling node
                BTreeNode<T>[] childNodes = parentNode._childNodes;

                for (int k = currentNode._k + 1; k < 256; k++)
                {
                    if (childNodes[k] != null)
                        return childNodes[k];
                }

                //no next sibling available; move up to parent node
                currentNode = parentNode;
            }
        }

        private BTreeNode<T> GetPreviousNode()
        {
            if (this._parentNode == null)
                return null; //current node is root node

            //find previous sibling node
            BTreeNode<T> currentNode = this;

            while (true)
            {
                BTreeNode<T> parentNode = currentNode._parentNode;

                if (parentNode == null)
                    return currentNode; //current node is root node

                //find previous sibling node
                BTreeNode<T>[] childNodes = parentNode._childNodes;

                for (int k = currentNode._k - 1; k > -1; k--)
                {
                    if (childNodes[k] != null)
                        return childNodes[k].GetLastNode();
                }

                //no previous sibling available; move up to parent node
                currentNode = parentNode;
            }
        }

        private void SetValue(byte[] key, T value)
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                if (key.Length == currentNode._depth)
                {
                    currentNode._nodeValue = new BTreeNodeValue<T>(key, value);
                    return;
                }

                if (key.Length < currentNode._depth)
                    return;

                if (currentNode._childNodes == null)
                {
                    if (currentNode._holdValue == null)
                    {
                        currentNode._holdValue = new BTreeNodeValue<T>(key, value);
                        return;
                    }
                    else
                    {
                        currentNode._childNodes = new BTreeNode<T>[256];

                        byte k = currentNode._holdValue.Key[currentNode._depth];

                        BTreeNode<T> childNode = new BTreeNode<T>(currentNode, k);
                        currentNode._childNodes[k] = childNode;

                        childNode.SetValue(currentNode._holdValue.Key, currentNode._holdValue.Value);
                        currentNode._holdValue = null;
                    }
                }

                {
                    byte k = key[currentNode._depth];
                    BTreeNode<T> childNode = currentNode._childNodes[k];

                    if (childNode == null)
                    {
                        childNode = new BTreeNode<T>(currentNode, k);
                        currentNode._childNodes[k] = childNode;
                    }

                    currentNode = childNode;
                }
            }
        }

        private BTreeNodeValue<T> GetValue(byte[] key)
        {
            if (key.Length == this._depth)
            {
                return _nodeValue;
            }
            else
            {
                if (_holdValue == null)
                    return null;

                byte[] holdKey = _holdValue.Key;

                if (holdKey.Length != key.Length)
                    return null;

                for (int i = 0; i < key.Length; i++)
                {
                    if (holdKey[i] != key[i])
                        return null;
                }

                return _holdValue;
            }
        }

        private BTreeNodeValue<T> RemoveValue(byte[] key)
        {
            if (key.Length == this._depth)
            {
                BTreeNodeValue<T> value = _nodeValue;
                _nodeValue = null;

                return value;
            }
            else
            {
                if (_holdValue == null)
                    return null;

                byte[] holdKey = _holdValue.Key;

                if (holdKey.Length != key.Length)
                    return null;

                for (int i = 0; i < key.Length; i++)
                {
                    if (holdKey[i] != key[i])
                        return null;
                }

                BTreeNodeValue<T> value = _holdValue;
                _holdValue = null;

                return value;
            }
        }

        #endregion

        #region public

        public void Insert(byte[] key, T value)
        {
            BTreeNode<T> node = FindClosestNode(key);
            BTreeNodeValue<T> v = node.GetValue(key);

            if (v != null)
                throw new Exception("Value already exists.");

            node.SetValue(key, value);
        }

        public void Upsert(byte[] key, T value)
        {
            BTreeNode<T> node = FindClosestNode(key);

            node.SetValue(key, value);
        }

        public bool Exists(byte[] key)
        {
            BTreeNode<T> node = FindClosestNode(key);
            BTreeNodeValue<T> value = node.GetValue(key);

            return (value != null);
        }

        public T Get(byte[] key)
        {
            BTreeNode<T> node = FindClosestNode(key);
            BTreeNodeValue<T> value = node.GetValue(key);

            if (value == null)
                return default(T);

            return value.Value;
        }

        public T Remove(byte[] key)
        {
            BTreeNode<T> node = FindClosestNode(key);
            BTreeNodeValue<T> value = node.RemoveValue(key);

            if (value == null)
                return default(T);

            return value.Value;
        }

        public IEnumerator<BTreeNodeValue<T>> GetEnumerator()
        {
            return new BTreeNodeForwardEnumerator(this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new BTreeNodeForwardEnumerator(this);
        }

        public IEnumerator<BTreeNodeValue<T>> GetReverseEnumerator()
        {
            return new BTreeNodeReverseEnumerator(this);
        }

        #endregion

        private abstract class BTreeNodeEnumerator : IEnumerator<BTreeNodeValue<T>>
        {
            #region enum

            protected enum ValueType
            {
                None = 0,
                NodeValue = 1,
                HoldValue = 2
            }

            #endregion

            #region variables

            protected BTreeNode<T> _rootNode;
            protected BTreeNode<T> _currentNode;
            protected BTreeNodeValue<T> _currentValue;
            protected ValueType _currentValueType = ValueType.None;

            #endregion

            #region constructor

            public BTreeNodeEnumerator(BTreeNode<T> rootNode, BTreeNode<T> currentNode)
            {
                _rootNode = rootNode;
                _currentNode = currentNode;
            }

            #endregion

            #region public

            public void Dispose()
            {
                //do nothing
            }

            public BTreeNodeValue<T> Current
            {
                get { return _currentValue; }
            }

            object IEnumerator.Current
            {
                get { return _currentValue; }
            }

            public void Reset()
            {
                _currentNode = _rootNode;
                _currentValue = null;
                _currentValueType = ValueType.None;
            }

            public abstract bool MoveNext();

            #endregion
        }

        private class BTreeNodeForwardEnumerator : BTreeNodeEnumerator
        {
            #region constructor

            public BTreeNodeForwardEnumerator(BTreeNode<T> rootNode)
                : base(rootNode, rootNode)
            { }

            #endregion

            #region public

            public override bool MoveNext()
            {
                while (true)
                {
                    if (_currentNode == null)
                    {
                        _currentValue = null;
                        return false;
                    }

                    if (_currentValueType == ValueType.None)
                    {
                        if (_currentNode._nodeValue != null)
                        {
                            _currentValue = _currentNode._nodeValue;
                            _currentValueType = ValueType.NodeValue;
                            return true;
                        }
                        else if (_currentNode._holdValue != null)
                        {
                            _currentValue = _currentNode._holdValue;
                            _currentValueType = ValueType.HoldValue;
                            return true;
                        }
                    }
                    else if (_currentValueType == ValueType.NodeValue)
                    {
                        if (_currentNode._holdValue != null)
                        {
                            _currentValue = _currentNode._holdValue;
                            _currentValueType = ValueType.HoldValue;
                            return true;
                        }
                    }

                    //move to next node
                    _currentNode = _currentNode.GetNextNode();
                    _currentValueType = ValueType.None;
                }
            }

            #endregion
        }

        private class BTreeNodeReverseEnumerator : BTreeNodeEnumerator
        {
            #region constructor

            public BTreeNodeReverseEnumerator(BTreeNode<T> rootNode)
                : base(rootNode, rootNode.GetLastNode())
            { }

            #endregion

            #region public

            public override bool MoveNext()
            {
                while (true)
                {
                    if (_currentNode == null)
                    {
                        _currentValue = null;
                        return false;
                    }

                    if (_currentValueType == ValueType.None)
                    {
                        if (_currentNode._holdValue != null)
                        {
                            _currentValue = _currentNode._holdValue;
                            _currentValueType = ValueType.HoldValue;
                            return true;
                        }
                        else if (_currentNode._nodeValue != null)
                        {
                            _currentValue = _currentNode._nodeValue;
                            _currentValueType = ValueType.NodeValue;
                            return true;
                        }
                    }
                    else if (_currentValueType == ValueType.HoldValue)
                    {
                        if (_currentNode._nodeValue != null)
                        {
                            _currentValue = _currentNode._nodeValue;
                            _currentValueType = ValueType.NodeValue;
                            return true;
                        }
                    }

                    //move to previous node
                    _currentNode = _currentNode.GetPreviousNode();
                    _currentValueType = ValueType.None;
                }
            }

            #endregion
        }
    }
}
