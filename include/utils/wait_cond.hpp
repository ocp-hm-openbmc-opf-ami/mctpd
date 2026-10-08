/*
// Copyright (c) 2023 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

class WaitCondition
{
  public:
    WaitCondition(const WaitCondition&) = delete;
    WaitCondition(WaitCondition&&) = default;

    using Timer = boost::asio::deadline_timer;
    using TimerPtr = std::shared_ptr<Timer>;
    using Timeout = boost::posix_time::millisec;

    class Lock
    {
      public:
        inline Lock(TimerPtr existingTimer) : unlockTimer(existingTimer)
        {
        }

        Lock() = default;
        Lock(Lock&&) = default;
        Lock(const Lock&) = delete;

        inline ~Lock()
        {
            if (unlockTimer)
            {
                unlockTimer->cancel();
            }
        }

        inline operator bool() const
        {
            return unlockTimer != nullptr;
        }

      private:
        TimerPtr unlockTimer = nullptr;
    };

    inline WaitCondition(boost::asio::io_context& ioc) :
        io(ioc), timer(std::make_shared<boost::asio::deadline_timer>(ioc))
    {
    }

    inline Lock lock(boost::asio::yield_context yield, Timeout timeout)
    {
        if (timer.use_count() == 1)
        {
            // No coroutine pending
            return Lock(timer);
        }
        // timer.use_count() is supposed to be either 1 or 2. Any other value is
        // an incorrect usage or some undiscovered error in implementation.
        else if (timer.use_count() > 1)
        {
            // Coroutine pending
            boost::system::error_code ec;
            auto copy = std::move(timer);
            copy->expires_from_now(timeout);

            timer = std::make_shared<Timer>(io);
            auto lock = Lock(timer);

            copy->async_wait(yield[ec]);
            if (ec == boost::system::errc::timed_out)
            {
                return Lock();
            }

            return lock;
        }

        // This is exception
        return Lock();
    }

  protected:
    boost::asio::io_context& io;
    TimerPtr timer;
};
