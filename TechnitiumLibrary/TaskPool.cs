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
        readonly ChannelWriter<KeyValuePair<object, Func<object, Task>>> _channelWriter;

        #endregion

        #region constructors

        public TaskPool(int queueSize = -1, int maximumConcurrencyLevel = -1, TaskScheduler taskScheduler = null)
        {
            if (maximumConcurrencyLevel < 1)
                maximumConcurrencyLevel = Environment.ProcessorCount;

            if (taskScheduler is null)
                taskScheduler = TaskScheduler.Default;

            _queueSize = queueSize;
            _maximumConcurrencyLevel = maximumConcurrencyLevel;

            if (_queueSize < 1)
            {
                _channel = Channel.CreateUnbounded<KeyValuePair<object, Func<object, Task>>>();
            }
            else
            {
                BoundedChannelOptions options = new BoundedChannelOptions(_queueSize);
                options.FullMode = BoundedChannelFullMode.DropWrite;

                _channel = Channel.CreateBounded<KeyValuePair<object, Func<object, Task>>>(options);
            }

            _channelWriter = _channel.Writer;
            ChannelReader<KeyValuePair<object, Func<object, Task>>> channelReader = _channel.Reader;

            for (int i = 0; i < _maximumConcurrencyLevel; i++)
            {
                Task.Factory.StartNew(async delegate ()
                {
                    await foreach (KeyValuePair<object, Func<object, Task>> task in channelReader.ReadAllAsync())
                    {
                        if (_disposed)
                            break;

                        await task.Value(task.Key);
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

            _channelWriter?.TryComplete();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region public

        public bool TryQueueTask(Func<object, Task> task)
        {
            return TryQueueTask(task, null);
        }

        public bool TryQueueTask(Func<object, Task> task, object state)
        {
            return _channelWriter.TryWrite(new KeyValuePair<object, Func<object, Task>>(state, task));
        }

        public async Task StopAndWaitForCompletionAsync()
        {
            if (_channelWriter.TryComplete())
                await _channel.Reader.Completion;
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
