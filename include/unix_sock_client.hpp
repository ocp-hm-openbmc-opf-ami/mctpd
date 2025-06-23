/*
// Copyright (c) 2025 Intel Corporation
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
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/spawn.hpp>
#include <phosphor-logging/log.hpp>
#include <unix_sock_intf.hpp>

class SocketInterface
{
  public:
    boost::asio::local::stream_protocol::socket socket;
    boost::asio::streambuf buffer;

    SocketInterface(boost::asio::io_context& io, uint32_t deviceEid);

    ~SocketInterface();

    void writeSocketAsync(const std::vector<uint8_t>& data, size_t len,
                          boost::asio::yield_context yield);
    std::pair<boost::system::error_code, std::vector<uint8_t>>
        startReceiving(boost::asio::yield_context yield);

    std::pair<boost::system::error_code, std::vector<uint8_t>>
        receiveCompleteMessage();

    void writeSocket(const std::vector<uint8_t>& data, size_t len);
};
