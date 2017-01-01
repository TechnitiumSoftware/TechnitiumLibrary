/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

using System.Collections;
using System.Collections.Generic;
using System.Threading;

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

        ReaderWriterLockSlim _nodeLock = new ReaderWriterLockSlim();
        ReaderWriterLockSlim _nodeValueLock = new ReaderWriterLockSlim();

        #endregion

        #region constructor

        public BTreeNode()
            : this(null, 0)
        { }

        private BTreeNode(BTreeNode<T> parentNode, byte k)
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
                ReaderWriterLockSlim _currentNodeLock = currentNode._nodeLock;
                _currentNodeLock.EnterReadLock();
                try
                {
                    if (currentNode._childNodes == null)
                        return currentNode;

                    int k = key[i];
                    BTreeNode<T> childNode = currentNode._childNodes[k];

                    if (childNode == null)
                        return currentNode;

                    currentNode = childNode;
                }
                finally
                {
                    _currentNodeLock.ExitReadLock();
                }
            }

            return currentNode;
        }

        private BTreeNode<T> GetLastNode()
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                ReaderWriterLockSlim _currentNodeLock = currentNode._nodeLock;
                _currentNodeLock.EnterReadLock();
                try
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
                finally
                {
                    _currentNodeLock.ExitReadLock();
                }
            }
        }

        private BTreeNode<T> GetNextNode()
        {
            _nodeLock.EnterReadLock();
            try
            {
                if (_childNodes != null)
                {
                    //return first non-null child node
                    foreach (BTreeNode<T> childNode in _childNodes)
                    {
                        if (childNode != null)
                            return childNode;
                    }
                }
            }
            finally
            {
                _nodeLock.ExitReadLock();
            }

            //no child nodes available, move up to parent node & find next sibling node
            BTreeNode<T> currentNode = this;

            while (true)
            {
                BTreeNode<T> parentNode = currentNode._parentNode;

                if (parentNode == null)
                    return null; //current node is root node

                parentNode._nodeLock.EnterReadLock();
                try
                {
                    //find next sibling node
                    BTreeNode<T>[] childNodes = parentNode._childNodes;

                    for (int k = currentNode._k + 1; k < 256; k++)
                    {
                        if (childNodes[k] != null)
                            return childNodes[k];
                    }
                }
                finally
                {
                    parentNode._nodeLock.ExitReadLock();
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

                parentNode._nodeLock.EnterReadLock();
                try
                {
                    //find previous sibling node
                    BTreeNode<T>[] childNodes = parentNode._childNodes;

                    for (int k = currentNode._k - 1; k > -1; k--)
                    {
                        if (childNodes[k] != null)
                            return childNodes[k].GetLastNode();
                    }
                }
                finally
                {
                    parentNode._nodeLock.ExitReadLock();
                }

                //no previous sibling available; check if parent has value set
                _parentNode._nodeValueLock.EnterReadLock();
                try
                {
                    if (_parentNode._nodeValue != null)
                        return _parentNode;
                }
                finally
                {
                    _parentNode._nodeValueLock.ExitReadLock();
                }

                //move up to parent node
                currentNode = parentNode;
            }
        }

        private BTreeNodeValue<T> SetValue(byte[] key, T value)
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                if (key.Length == currentNode._depth)
                {
                    currentNode._nodeValueLock.EnterWriteLock();
                    try
                    {
                        BTreeNodeValue<T> oldValue = currentNode._nodeValue;
                        currentNode._nodeValue = new BTreeNodeValue<T>(key, value);

                        return oldValue;
                    }
                    finally
                    {
                        currentNode._nodeValueLock.ExitWriteLock();
                    }
                }

                if (key.Length < currentNode._depth)
                    throw new BTreeException("Cannot set value since the key length is less than node depth.");

                ReaderWriterLockSlim currentNodeLock = currentNode._nodeLock;
                currentNodeLock.EnterWriteLock();
                try
                {
                    if (currentNode._childNodes == null)
                    {
                        if (currentNode._holdValue == null)
                        {
                            //set value into current node hold
                            BTreeNodeValue<T> oldValue = currentNode._holdValue;
                            currentNode._holdValue = new BTreeNodeValue<T>(key, value);

                            return oldValue;
                        }

                        //explode current node & move hold value to child node
                        {
                            currentNode._childNodes = new BTreeNode<T>[256];

                            byte k = currentNode._holdValue.Key[currentNode._depth];

                            BTreeNode<T> childNode = new BTreeNode<T>(currentNode, k);
                            currentNode._childNodes[k] = childNode;

                            if (currentNode._holdValue.Key.Length == childNode._depth)
                                childNode._nodeValue = currentNode._holdValue;
                            else
                                childNode._holdValue = currentNode._holdValue;

                            currentNode._holdValue = null;
                        }
                    }

                    //set child node as current node
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
                finally
                {
                    currentNodeLock.ExitWriteLock();
                }
            }
        }

        private BTreeNodeValue<T> GetValue(byte[] key)
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                if (key.Length == currentNode._depth)
                {
                    currentNode._nodeValueLock.EnterReadLock();
                    try
                    {
                        return currentNode._nodeValue;
                    }
                    finally
                    {
                        currentNode._nodeValueLock.ExitReadLock();
                    }
                }

                if (key.Length < currentNode._depth)
                    throw new BTreeException("Cannot get value since the key length is less than node depth.");

                ReaderWriterLockSlim currentNodeLock = currentNode._nodeLock;
                currentNodeLock.EnterReadLock();
                try
                {
                    if (currentNode._childNodes == null)
                    {
                        //check and return hold value
                        if (currentNode._holdValue == null)
                            return null;

                        byte[] holdKey = currentNode._holdValue.Key;

                        if (holdKey.Length != key.Length)
                            return null;

                        for (int i = 0; i < key.Length; i++)
                        {
                            if (holdKey[i] != key[i])
                                return null;
                        }

                        return currentNode._holdValue;
                    }

                    //set child node as current node
                    {
                        byte k = key[currentNode._depth];
                        BTreeNode<T> childNode = currentNode._childNodes[k];

                        if (childNode == null)
                        {
                            //no value set in child node
                            return null;
                        }

                        currentNode = childNode;
                    }
                }
                finally
                {
                    currentNodeLock.ExitReadLock();
                }
            }
        }

        private BTreeNodeValue<T> RemoveValue(byte[] key)
        {
            BTreeNode<T> currentNode = this;

            while (true)
            {
                if (key.Length == currentNode._depth)
                {
                    currentNode._nodeValueLock.EnterWriteLock();
                    try
                    {
                        BTreeNodeValue<T> oldValue = currentNode._nodeValue;
                        currentNode._nodeValue = null;

                        return oldValue;
                    }
                    finally
                    {
                        currentNode._nodeValueLock.ExitWriteLock();
                    }
                }

                if (key.Length < currentNode._depth)
                    throw new BTreeException("Cannot remove value since the key length is less than node depth.");

                ReaderWriterLockSlim currentNodeLock = currentNode._nodeLock;
                currentNodeLock.EnterWriteLock();
                try
                {
                    if (currentNode._childNodes == null)
                    {
                        //check and remove hold value
                        if (currentNode._holdValue == null)
                            return null;

                        byte[] holdKey = currentNode._holdValue.Key;

                        if (holdKey.Length != key.Length)
                            return null;

                        for (int i = 0; i < key.Length; i++)
                        {
                            if (holdKey[i] != key[i])
                                return null;
                        }

                        BTreeNodeValue<T> oldValue = currentNode._holdValue;
                        currentNode._holdValue = null;

                        return oldValue;
                    }

                    //set child node as current node
                    {
                        byte k = key[currentNode._depth];
                        BTreeNode<T> childNode = currentNode._childNodes[k];

                        if (childNode == null)
                        {
                            //no value set in child node
                            return null;
                        }

                        currentNode = childNode;
                    }
                }
                finally
                {
                    currentNodeLock.ExitWriteLock();
                }
            }
        }

        #endregion

        #region public

        public void Insert(byte[] key, T value)
        {
            BTreeNode<T> node = FindClosestNode(key);
            BTreeNodeValue<T> v = node.GetValue(key);

            if (v != null)
                throw new BTreeException("Value already exists.");

            node.SetValue(key, value);
        }

        public T Upsert(byte[] key, T value)
        {
            BTreeNode<T> node = FindClosestNode(key);

            return node.SetValue(key, value).Value;
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

        public IEnumerable<BTreeNodeValue<T>> GetReverseEnumerable()
        {
            return new ReverseBTree(this);
        }

        #endregion

        private class ReverseBTree : IEnumerable<BTreeNodeValue<T>>
        {
            #region variables

            BTreeNode<T> _node;

            #endregion

            #region constructor

            public ReverseBTree(BTreeNode<T> node)
            {
                _node = node;
            }

            #endregion

            #region public

            public IEnumerator<BTreeNodeValue<T>> GetEnumerator()
            {
                return new BTreeNodeReverseEnumerator(_node);
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return new BTreeNodeReverseEnumerator(_node);
            }

            #endregion
        }

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
                        _currentNode._nodeValueLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._nodeValue != null)
                            {
                                _currentValue = _currentNode._nodeValue;
                                _currentValueType = ValueType.NodeValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeValueLock.ExitReadLock();
                        }

                        _currentNode._nodeLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._holdValue != null)
                            {
                                _currentValue = _currentNode._holdValue;
                                _currentValueType = ValueType.HoldValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeLock.ExitReadLock();
                        }
                    }
                    else if (_currentValueType == ValueType.NodeValue)
                    {
                        _currentNode._nodeLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._holdValue != null)
                            {
                                _currentValue = _currentNode._holdValue;
                                _currentValueType = ValueType.HoldValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeLock.ExitReadLock();
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
                        _currentNode._nodeLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._holdValue != null)
                            {
                                _currentValue = _currentNode._holdValue;
                                _currentValueType = ValueType.HoldValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeLock.ExitReadLock();
                        }


                        _currentNode._nodeValueLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._nodeValue != null)
                            {
                                _currentValue = _currentNode._nodeValue;
                                _currentValueType = ValueType.NodeValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeValueLock.ExitReadLock();
                        }
                    }
                    else if (_currentValueType == ValueType.HoldValue)
                    {
                        _currentNode._nodeValueLock.EnterReadLock();
                        try
                        {
                            if (_currentNode._nodeValue != null)
                            {
                                _currentValue = _currentNode._nodeValue;
                                _currentValueType = ValueType.NodeValue;
                                return true;
                            }
                        }
                        finally
                        {
                            _currentNode._nodeValueLock.ExitReadLock();
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
