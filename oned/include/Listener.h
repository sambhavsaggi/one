/* -------------------------------------------------------------------------- */
/* Copyright 2002-2019, OpenNebula Project, OpenNebula Systems                */
/*                                                                            */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License. You may obtain    */
/* a copy of the License at                                                   */
/*                                                                            */
/* http://www.apache.org/licenses/LICENSE-2.0                                 */
/*                                                                            */
/* Unless required by applicable law or agreed to in writing, software        */
/* distributed under the License is distributed on an "AS IS" BASIS,          */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   */
/* See the License for the specific language governing permissions and        */
/* limitations under the License.                                             */
/* -------------------------------------------------------------------------- */

#ifndef LISTENER_H_
#define LISTENER_H_

#include <functional>
#include <queue>
#include <atomic>
#include <mutex>
#include <chrono>
#include <condition_variable>
#include <thread>

#include <iostream>
/**
 *  The Timer class executes a given action periodically in a separate thread.
 *  The thread is terminated when the object is deleted
 */
class Timer
{
public:
    Timer(int s, std::function<void()> timer)
    {
        end = false;

        timer_thread = std::thread([&, s, timer]{

            std::unique_lock<std::mutex> ul(lock);

            while(true)
            {
                bool tout = cond.wait_for(ul, std::chrono::seconds(s), [&]{
                        return end == true;
                });

                if (end)
                {
                    return;
                }
                else if (!tout)
                {
                    timer();
                }
            }
        });
    };

    ~Timer()
    {
        end = true;

        cond.notify_one();

        timer_thread.join();
    }

private:
    std::atomic<bool> end;

    std::thread timer_thread;

    std::mutex lock;
    std::condition_variable cond;
};

/**
 *  This class implements basic functionality to listen for events. Events are
 *  triggered in separate threads. The class store them in a queue and executed
 *  them in the listner thread.
 */
class Listener
{
public:
    /**
     *  Trigger an event in the listner. For example:
     *    listener.trigger(std::bind(&Class::callback, this, param1, param2);
     *
     *    @param f, callback function for the event
     */
    void trigger(std::function<void()> f)
    {
        std::unique_lock<std::mutex> ul(lock);

        pending.push(f);

        ul.unlock();

        cond.notify_one();
    }

    /**
     *  Starts the event loop waiting for events.
     */
    void start()
    {
        end = false;

        std::unique_lock<std::mutex> ul(lock);

        while(true)
        {
            cond.wait(ul, [&]{return (end || !pending.empty());});

            if (end)
            {
                return;
            }

            auto fn = pending.front();
            pending.pop();

            fn();
        }
    }

    /**
     *  Stops the event loop
     */
    void finalize()
    {
        end = true;

        cond.notify_one();
    }

private:

    std::atomic<bool> end;

    std::mutex lock;
    std::condition_variable cond;

    std::queue<std::function<void()>> pending;
};

#endif /*LISTENER_H_*/
