/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Channels;
using System.Threading.Tasks;

namespace TechnitiumLibrary
{
    public sealed class TaskPool : IDisposable
    {
        #region variables

        readonly int _queueSize;
        readonly int _maximumConcurrencyLevel;

        readonly Channel<KeyValuePair<object, Func<object, Task>>> _channel;

        #endregion

        #region constructors

        public TaskPool()
            : this(-1)
        { }

        public TaskPool(int queueSize)
            : this(queueSize, Environment.ProcessorCount)
        { }

        public TaskPool(int queueSize, int maximumConcurrencyLevel)
            : this(queueSize, maximumConcurrencyLevel, TaskScheduler.Default)
        { }

        public TaskPool(int queueSize, int maximumConcurrencyLevel, TaskScheduler taskScheduler)
        {
            if (maximumConcurrencyLevel < 1)
                throw new ArgumentOutOfRangeException(nameof(maximumConcurrencyLevel), "Value cannot be less than 1.");

            _queueSize = queueSize;
            _maximumConcurrencyLevel = maximumConcurrencyLevel;

            if (_queueSize < 1)
                _channel = Channel.CreateUnbounded<KeyValuePair<object, Func<object, Task>>>();
            else
                _channel = Channel.CreateBounded<KeyValuePair<object, Func<object, Task>>>(new BoundedChannelOptions(_queueSize));

            ChannelReader<KeyValuePair<object, Func<object, Task>>> channelReader = _channel.Reader;

            for (int i = 0; i < _maximumConcurrencyLevel; i++)
            {
                Task.Factory.StartNew(async delegate ()
                {
                    while (!_disposed)
                    {
                        try
                        {
                            KeyValuePair<object, Func<object, Task>> task = await channelReader.ReadAsync();

                            await task.Value(task.Key);
                        }
                        catch (ChannelClosedException)
                        {
                            break;
                        }
                        catch
                        { }
                    }
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, taskScheduler);
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _channel?.Writer.TryComplete();

            _disposed = true;
        }

        #endregion

        #region public

        public bool TryQueueTask(Func<object, Task> task)
        {
            return TryQueueTask(task, null);
        }

        public bool TryQueueTask(Func<object, Task> task, object state)
        {
            return _channel.Writer.TryWrite(new KeyValuePair<object, Func<object, Task>>(state, task));
        }

        public void Stop()
        {
            _channel.Writer.TryComplete();
        }

        #endregion

        #region properties

        public int QueueSize
        { get { return _queueSize; } }

        public int MaximumConcurrencyLevel
        { get { return _maximumConcurrencyLevel; } }

        #endregion
    }
}
