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

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <cstdint>
#include <string>

class MctpBinding;
namespace unix_ipc
{

namespace unix_path
{
std::string getPIDStr();
std::string getSockPath();
} // namespace unix_path

namespace unix_protocol
{
enum class OpCode : uint8_t
{
    sendReceive,
    sendOnly,
    broadCastResponse,
    directedResponse
};

struct SendReceiveRequest
{
    uint16_t timeOut;
} __attribute__((packed));

struct Message
{
    uint8_t eid;
    OpCode opCode;
    uint16_t len;
    int32_t errorCode;
} __attribute__((packed));
} // namespace unix_protocol

class Session
{
  public:
    Session(boost::asio::local::stream_protocol::socket skt,
            boost::asio::io_context& ioc, MctpBinding& obj,
            unsigned long token) :
        socket(std::move(skt)), io(ioc), mctp(obj), sessionID(token)
    {
    }
    ~Session() = default;
    void run();
    void writeSocket(const std::vector<uint8_t>& response);

  private:
    void waitForRequest();
    boost::asio::local::stream_protocol::socket socket;
    boost::asio::io_context& io;
    MctpBinding& mctp;
    unsigned long sessionID;
    boost::asio::streambuf buffer;
};

void addSessionToList(unsigned long connectionCount,
                      std::shared_ptr<Session> connection);

} // namespace unix_ipc
