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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary
{
    public sealed class IndependentTaskScheduler : TaskScheduler, IDisposable
    {
        #region variables

        readonly int _maximumConcurrencyLevel;
        readonly ThreadPriority _priority;

        readonly HashSet<Thread> _threads;
        readonly BlockingCollection<Task> _tasks = new BlockingCollection<Task>();

        #endregion

        #region constructors

        public IndependentTaskScheduler(int maximumConcurrencyLevel = -1, ThreadPriority priority = ThreadPriority.Normal, string threadName = null)
        {
            if (maximumConcurrencyLevel < 1)
                maximumConcurrencyLevel = Environment.ProcessorCount;

            _maximumConcurrencyLevel = maximumConcurrencyLevel;
            _priority = priority;

            _threads = new HashSet<Thread>(_maximumConcurrencyLevel);

            for (int i = 0; i < _maximumConcurrencyLevel; i++)
            {
                Thread thread = new Thread(delegate ()
                {
                    try
                    {
                        foreach (Task task in _tasks.GetConsumingEnumerable())
                            TryExecuteTask(task);
                    }
                    catch (ObjectDisposedException)
                    { }
                });

                thread.Name = threadName ?? GetType().Name;
                thread.IsBackground = true;
                thread.Priority = _priority;
                thread.Start();

                if (!_threads.Add(thread))
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _tasks?.Dispose();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region protected

        protected override IEnumerable<Task> GetScheduledTasks()
        {
            return _tasks;
        }

        protected override void QueueTask(Task task)
        {
            if (task.CreationOptions.HasFlag(TaskCreationOptions.LongRunning))
            {
                Thread thread = new Thread(delegate ()
                {
                    TryExecuteTask(task);
                });

                thread.Name = this.GetType().Name;
                thread.IsBackground = true;
                thread.Priority = _priority;
                thread.Start();
            }
            else
            {
                try
                {
                    _tasks.Add(task);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued)
        {
            if (_threads.Contains(Thread.CurrentThread))
                return TryExecuteTask(task);

            return false;
        }

        #endregion

        #region properties

        public override int MaximumConcurrencyLevel
        { get { return _maximumConcurrencyLevel; } }

        #endregion
    }
}
