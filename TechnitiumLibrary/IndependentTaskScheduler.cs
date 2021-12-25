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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary
{
    public class IndependentTaskScheduler : TaskScheduler
    {
        #region variables

        readonly int _maximumConcurrencyLevel;
        readonly ThreadPriority _priority;

        readonly List<Thread> _threads;
        readonly BlockingCollection<Task> _tasks = new BlockingCollection<Task>();

        #endregion

        #region constructors

        public IndependentTaskScheduler(ThreadPriority priority = ThreadPriority.Normal)
            : this(Math.Max(1, Environment.ProcessorCount), priority)
        { }

        public IndependentTaskScheduler(int maximumConcurrencyLevel, ThreadPriority priority = ThreadPriority.Normal)
        {
            _maximumConcurrencyLevel = maximumConcurrencyLevel;
            _priority = priority;

            _threads = new List<Thread>(_maximumConcurrencyLevel);

            for (int i = 0; i < _maximumConcurrencyLevel; i++)
            {
                Thread thread = new Thread(delegate ()
                {
                    foreach (Task task in _tasks.GetConsumingEnumerable())
                        TryExecuteTask(task);
                });

                thread.Name = this.GetType().Name;
                thread.IsBackground = true;
                thread.Priority = _priority;
                thread.Start();

                _threads.Add(thread);
            }
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
                _tasks.Add(task);
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
