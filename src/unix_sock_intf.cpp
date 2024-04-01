/*
// Copyright (c) 2024 Intel Corporation
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

#include "unix_sock_intf.hpp"

#include <unistd.h>

#include <filesystem>

namespace unix_ipc
{
namespace unix_path
{
constexpr char unixSktAbsPath[] = "\0mctp";
constexpr size_t unixSktAbsPathLen = sizeof(unixSktAbsPath) - 1;

std::string getPIDStr()
{
    return std::to_string(getpid());
}

std::string getSockPath()
{
    std::string path(unixSktAbsPath, unixSktAbsPathLen);
    return (path + getPIDStr());
}
} // namespace unix_path

using It = boost::asio::buffers_iterator<boost::asio::const_buffers_1>;
std::pair<It, bool> isCompleteRequest(It begin, It end)
{

    auto distance = std::distance(begin, end);
    if (distance > std::numeric_limits<uint16_t>::max())
    {
        return std::make_pair(begin, false);
    }

    if (distance < static_cast<int>(sizeof(unix_protocol::Message)))
    {
        return std::make_pair(begin, false);
    }

    unix_protocol::Message msg;
    std::copy(begin, std::next(begin, sizeof(msg)),
              reinterpret_cast<uint8_t*>(&msg));
    auto expectedSize = le16toh(msg.len);
    if (distance >= expectedSize)
    {
        return std::make_pair(std::next(begin, expectedSize), true);
    }
    else
    {
        return std::make_pair(begin, false);
    }
}

void Session::waitForRequest()
{
    boost::asio::async_read_until(
        socket, buffer, isCompleteRequest,
        [this](boost::system::error_code ec, std::size_t length) {
            if (ec || length == 0)
            {
                if (ec == boost::asio::error::eof)
                {
                    /*
                    other end of the socket is closed,need to remove the session
                    info ToDo:  will be pushed in upcoming PR
                    */
                }
                else
                {
                    this->waitForRequest();
                }
                return;
            }

            std::vector<uint8_t> reqBuf(length);
            boost::asio::buffer_copy(boost::asio::buffer(reqBuf),
                                     this->buffer.data(), length);
            buffer.consume(length);
            /*
            TODO:
            Will be adding the logic for processing received packet in next PR
            */
        });
}

} // namespace unix_ipc
