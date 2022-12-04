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
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary
{
    public static class TaskExtension
    {
        public static async Task WithTimeout(this Task task, int timeout)
        {
            using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
            {
                if (await Task.WhenAny(new Task[] { task, Task.Delay(timeout, timeoutCancellationTokenSource.Token) }) != task)
                    throw new TimeoutException();

                timeoutCancellationTokenSource.Cancel(); //to stop delay task
            }

            await task; //await again for any exception to be rethrown
        }

        public static async Task<T> WithTimeout<T>(this Task<T> task, int timeout)
        {
            using (CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource())
            {
                if (await Task.WhenAny(new Task[] { task, Task.Delay(timeout, timeoutCancellationTokenSource.Token) }) != task)
                    throw new TimeoutException();

                timeoutCancellationTokenSource.Cancel(); //to stop delay task
            }

            return await task; //await again for any exception to be rethrown
        }

        public static void Sync(this Task task)
        {
            task.ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public static T Sync<T>(this Task<T> task)
        {
            return task.ConfigureAwait(false).GetAwaiter().GetResult();
        }
    }
}
