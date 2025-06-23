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
#include "unix_sock_client.hpp"

#include <phosphor-logging/log.hpp>
using namespace unix_ipc;

SocketInterface::SocketInterface(boost::asio::io_context& io,
                                 uint32_t deviceEid) : socket(io)

{
    constexpr char unixSktAbsPath[] = "\0spdm";
    constexpr size_t unixSktAbsPathLen = sizeof(unixSktAbsPath) - 1;
    std::string path(unixSktAbsPath, unixSktAbsPathLen);
    path += std::to_string(deviceEid);
    boost::asio::local::stream_protocol::endpoint endpoint(path);
    socket.connect(endpoint);
}

SocketInterface::~SocketInterface()
{
    socket.shutdown(boost::asio::socket_base::shutdown_both);

    socket.close();
}

void SocketInterface::writeSocketAsync(const std::vector<uint8_t>& data,
                                       size_t len,
                                       boost::asio::yield_context yield)
{
    boost::system::error_code ec;

    boost::asio::async_write(socket, boost::asio::buffer(data.data(), len),
                             yield[ec]);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write socket failed");
    }
}

using iter = boost::asio::buffers_iterator<boost::asio::const_buffer>;

std::pair<iter, bool> isCompleteRequest(iter begin, iter end)
{
    auto distance = std::distance(begin, end);

    if (distance == 0)
    {
        return {begin, false};
    }

    if (distance > std::numeric_limits<uint16_t>::max())
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isCompleteRequest: Message size exceeds maximum allowed.");
        return {begin, false};
    }

    if (distance < static_cast<int>(sizeof(unix_protocol::Message)))
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isCompleteRequest: Message size is smaller than header size.");
        return {begin, false};
    }

    const unix_protocol::Message* msg =
        reinterpret_cast<const unix_protocol::Message*>(&*begin);
    auto expectedSize = le16toh(msg->len);

    if (distance < expectedSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Incomplete message received");
        return {begin, false};
    }

    return {std::next(begin, expectedSize), true};
}

std::pair<boost::system::error_code, std::vector<uint8_t>>
    SocketInterface::startReceiving(boost::asio::yield_context yield)
{
    boost::system::error_code ec;

    // Read until the message is complete based on isCompleteRequest
    boost::asio::async_read_until(socket, buffer, isCompleteRequest, yield[ec]);

    std::vector<uint8_t> payload;

    if (!ec)
    {
        auto bufBegin = boost::asio::buffers_begin(buffer.data());
        std::vector<uint8_t> receivedMessage(bufBegin,
                                             bufBegin + buffer.size());
        buffer.consume(buffer.size());

        if (receivedMessage.size() >= sizeof(unix_protocol::Message))
        {
            const auto* header =
                reinterpret_cast<const unix_protocol::Message*>(
                    receivedMessage.data());
            size_t payloadSize = header->len - sizeof(unix_protocol::Message);

            payload.reserve(payloadSize);
            payload.insert(payload.end(),
                           receivedMessage.begin() +
                               sizeof(unix_protocol::Message),
                           receivedMessage.begin() +
                               sizeof(unix_protocol::Message) + payloadSize);
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "startReceiving: Received message is too short.");
            ec = make_error_code(boost::system::errc::message_size);
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("startReceiving: Error receiving message: " + ec.message() +
             ", error code: " + std::to_string(ec.value()))
                .c_str());
    }

    return {ec, payload};
}

void SocketInterface::writeSocket(const std::vector<uint8_t>& data, size_t len)
{
    boost::system::error_code ec;

    boost::asio::write(socket, boost::asio::buffer(data.data(), len), ec);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Synchronous Write socket failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
    }
}

std::pair<boost::system::error_code, std::vector<uint8_t>>
    SocketInterface::receiveCompleteMessage()
{
    boost::system::error_code ec;
    boost::asio::streambuf buffer;
    std::vector<uint8_t> payload;

    while (true)
    {
        size_t len = boost::asio::read(socket, buffer.prepare(1024),
                                       boost::asio::transfer_at_least(1), ec);
        buffer.commit(len);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Sync : Error reading from socket",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            break;
        }

        // Check if we have received a complete message
        auto bufData = buffer.data();
        auto [it, complete] =
            isCompleteRequest(boost::asio::buffers_begin(bufData),
                              boost::asio::buffers_end(bufData));
        if (complete)
        {
            // Extract the header portion into a temporary vector for safe
            // casting
            std::vector<uint8_t> headerBytes(
                boost::asio::buffers_begin(bufData),
                boost::asio::buffers_begin(bufData) +
                    sizeof(unix_protocol::Message));
            const auto* header =
                reinterpret_cast<const unix_protocol::Message*>(
                    headerBytes.data());

            if (header->len >= sizeof(unix_protocol::Message))
            {
                auto payloadStart =
                    std::next(boost::asio::buffers_begin(bufData),
                              sizeof(unix_protocol::Message));
                auto payloadEnd = std::next(
                    payloadStart, header->len - sizeof(unix_protocol::Message));
                payload.assign(payloadStart, payloadEnd);
                buffer.consume(header->len);
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "receiveCompleteMessage: Received message is too short.",
                    phosphor::logging::entry("LEN=%d", header->len));
                ec = make_error_code(boost::system::errc::message_size);
            }
            break;
        }
    }

    return {ec, payload};
}