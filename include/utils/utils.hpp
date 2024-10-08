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
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/container/flat_map.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus/match.hpp>

static std::unique_ptr<sdbusplus::bus::match::match> powerMatch = nullptr;
static std::unique_ptr<sdbusplus::bus::match::match> hostResetMatch = nullptr;

namespace power
{
const static constexpr char* interface = "xyz.openbmc_project.State.Host";
const static constexpr char* path = "/xyz/openbmc_project/state/host0";
const static constexpr char* property = "CurrentHostState";
} // namespace power

namespace platform_state
{
const static constexpr char* interface = "xyz.openbmc_project.State.Host.Misc";
const static constexpr char* path = "/xyz/openbmc_project/misc/platform_state";
const static constexpr char* platResetProperty = "ESpiPlatformReset";
} // namespace platform_state

namespace properties
{
constexpr const char* interface = "org.freedesktop.DBus.Properties";
} // namespace properties

template <class T>
void setupPowerMatch(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const T& bindingPtr)
{
    if (powerMatch || bindingPtr == nullptr || conn == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to setup power match");
        return;
    }

    static boost::asio::steady_timer timer(conn->get_io_context());
    std::string matchString =
        sdbusplus::bus::match::rules::type::signal() +
        sdbusplus::bus::match::rules::interface(properties::interface) +
        sdbusplus::bus::match::rules::path(power::path) +
        sdbusplus::bus::match::rules::argN(0, power::interface);

    powerMatch = std::make_unique<sdbusplus::bus::match::match>(
        static_cast<sdbusplus::bus::bus&>(*conn), matchString,
        [bindingPtr](sdbusplus::message::message& message) {
            std::string objectName;
            boost::container::flat_map<std::string, std::variant<std::string>>
                values;
            message.read(objectName, values);
            auto findState = values.find(power::property);
            if (findState == values.end())
            {
                return;
            }

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Host State changed. Triggering device discovery");

            bool on = boost::ends_with(std::get<std::string>(findState->second),
                                       ".Running");

            // on and off comes too quickly
            int delayInSec = 5;
            if (on)
            {
                delayInSec = 10;
            }
            timer.expires_after(std::chrono::seconds(delayInSec));
            timer.async_wait([&](boost::system::error_code ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    // Host resets more than once while booting. This results in
                    // receiving more than one on/off signal during power on. In
                    // this case first instance of the timer will be aborted.
                    return;
                }
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("Timer error: ") + ec.message()).c_str());

                    return;
                }
                bindingPtr->triggerDeviceDiscovery();
            });
        });
}

template <class T>
void setupHostResetMatch(std::shared_ptr<sdbusplus::asio::connection> conn,
                         const T& bindingPtr)
{
    if (hostResetMatch || bindingPtr == nullptr || conn == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to setup host Reset match");
        return;
    }

    static boost::asio::steady_timer timer(conn->get_io_context());
    std::string matchString =
        sdbusplus::bus::match::rules::type::signal() +
        sdbusplus::bus::match::rules::interface(properties::interface) +
        sdbusplus::bus::match::rules::path(platform_state::path) +
        sdbusplus::bus::match::rules::argN(0, platform_state::interface);

    hostResetMatch = std::make_unique<sdbusplus::bus::match::match>(
        static_cast<sdbusplus::bus::bus&>(*conn), matchString,
        [bindingPtr](sdbusplus::message::message& message) {
            std::string objectName;
            boost::container::flat_map<std::string,
                                       std::variant<bool, std::string>>
                values;
            message.read(objectName, values);
            auto findState = values.find(platform_state::platResetProperty);
            if (findState == values.end())
            {
                return;
            }

            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Host Reset. Triggering device discovery");

            bool resetState = std::get<bool>(findState->second);

            if (!resetState)
            {
                // nothing to do
                return;
            }

            // wait for a second
            int delayInSec = 1;
            timer.expires_after(std::chrono::seconds(delayInSec));
            timer.async_wait([&](boost::system::error_code ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return;
                }
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("Timer error: ") + ec.message()).c_str());

                    return;
                }
                bindingPtr->triggerDeviceDiscovery();
            });
        });
}

inline std::string formatUUID(const guid_t& uuid)
{
    const size_t safeBufferLength = 50;
    char buf[safeBufferLength] = {0};
    auto ptr = reinterpret_cast<const uint8_t*>(&uuid);

    snprintf(
        buf, safeBufferLength,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8],
        ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15]);
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    return std::string(buf);
}

inline void throwRunTimeError(const std::string& err)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(err.c_str());
    throw std::runtime_error(err);
}

template <typename T>
T* castVectorToStruct(std::vector<uint8_t>& response)
{
    response.resize(sizeof(T));
    return reinterpret_cast<T*>(response.data());
}
