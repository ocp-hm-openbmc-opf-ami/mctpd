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

#include "MCTPBinding.hpp"

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

namespace session_list
{
static std::unordered_map<unsigned long, std::shared_ptr<Session>> sessionList;
}

void addSessionToList(unsigned long connectionCount,
                      std::shared_ptr<Session> connection)
{
    session_list::sessionList.insert(
        std::make_pair(connectionCount, std::move(connection)));
}

void fillHeader(std::vector<uint8_t>& response, unix_protocol::OpCode opCode,
                uint16_t len, uint8_t eid)
{
    unix_protocol::Message respMsg;
    respMsg.opCode = opCode;
    respMsg.len = len;
    respMsg.eid = eid;
    auto const ptr = reinterpret_cast<uint8_t*>(&respMsg);
    response.reserve(sizeof(unix_protocol::Message) + 1);
    std::copy(ptr, ptr + sizeof(unix_protocol::Message),
              std::back_inserter(response));
}

void Session::writeSocket(const std::vector<uint8_t>& response)
{

    boost::asio::write(socket,
                       boost::asio::buffer(response.data(), response.size()));
}

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
            boost::asio::spawn(io, [reqBuf = std::move(reqBuf),
                                    this](boost::asio::yield_context yield) {
                auto msg = reinterpret_cast<const unix_protocol::Message*>(
                    reqBuf.data());

                int len = 0;
                if (msg->opCode == unix_protocol::OpCode::sendReceive)
                {
                    len = sizeof(unix_protocol::SendReceiveRequest);

                    std::vector<uint8_t> payload(
                        reqBuf.begin() + sizeof(unix_protocol::Message) + len,
                        reqBuf.end());

                    auto timeOut =
                        reinterpret_cast<
                            const unix_protocol::SendReceiveRequest*>(
                            reqBuf.data() + sizeof(unix_protocol::Message))
                            ->timeOut;

                    auto resp = this->mctp.sendReceiveMctpMessagePayload(
                        yield, msg->eid, payload, timeOut);
                    std::vector<uint8_t> response;
                    fillHeader(
                        response, unix_protocol::OpCode::directedResponse,
                        static_cast<uint16_t>(resp.size() +
                                              sizeof(unix_protocol::Message)),
                        msg->eid);
                    response.insert(response.end(), resp.begin(), resp.end());
                    writeSocket(response);
                }
            });

            waitForRequest();
        });
}

void Session::run()
{
    waitForRequest();
}

} // namespace unix_ipc