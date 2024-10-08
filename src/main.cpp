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

#include "I3CBinding.hpp"
#include "MCTPBinding.hpp"
#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"
#include "hw/I3CDriver.hpp"
#include "hw/aspeed/I3CDriver.hpp"
#include "hw/aspeed/PCIeDriver.hpp"
#include "hw/aspeed/PCIeMonitor.hpp"

#include <CLI/CLI.hpp>
#include <boost/asio/signal_set.hpp>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

std::shared_ptr<MctpBinding>
    getBindingPtr(const Configuration& configuration,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<object_server>& objectServer,
                  boost::asio::io_context& ioc)
{
    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";

    if (auto smbusConfig =
            dynamic_cast<const SMBusConfiguration*>(&configuration))
    {
        return std::make_shared<SMBusBinding>(
            conn, objectServer, mctpBaseObj, *smbusConfig, ioc,
            std::make_unique<boost::asio::posix::stream_descriptor>(ioc));
    }
    else if (auto pcieConfig =
                 dynamic_cast<const PcieConfiguration*>(&configuration))
    {
        return std::make_shared<PCIeBinding>(
            conn, objectServer, mctpBaseObj, *pcieConfig, ioc,
            std::make_unique<hw::aspeed::PCIeDriver>(ioc),
            std::make_unique<hw::aspeed::PCIeMonitor>(ioc));
    }
    else if (auto i3cConfig =
                 dynamic_cast<const I3CConfiguration*>(&configuration))
    {
        std::optional<uint16_t> pidMask = std::nullopt;
        if (i3cConfig->requiresCpuPidMask)
        {
            pidMask = i3cConfig->provisionalIdMask;
        }

        return std::make_shared<I3CBinding>(
            conn, objectServer, mctpBaseObj, *i3cConfig, ioc,
            std::make_unique<hw::aspeed::I3CDriver>(ioc, i3cConfig->bus,
                                                    pidMask));
    }

    return nullptr;
}

int main(int argc, char* argv[])
{
    CLI::App app("MCTP Daemon");
    std::string binding;
    std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
        mctpdConfigurationPair;
    app.add_option("-b,--binding", binding,
                   "MCTP Physical Binding. Supported: -b smbus, -b pcie")
        ->required();
    CLI11_PARSE(app, argc, argv);
    boost::asio::io_context ioc;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    std::shared_ptr<MctpBinding> bindingPtr;
    signals.async_wait(
        [&ioc, &bindingPtr](const boost::system::error_code&, const int&) {
            // Ensure we destroy binding object before we do an ioc stop
            bindingPtr.reset();
            ioc.stop();
        });

    auto conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    /* Process configuration */
    try
    {
        mctpdConfigurationPair = getConfiguration(conn, binding);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid configuration; exiting");
        return -1;
    }

    if (!mctpdConfigurationPair)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Could not load any configuration; exiting");
        return -1;
    }

    auto& [mctpdName, mctpdConfiguration] = *mctpdConfigurationPair;
    auto objectServer = std::make_shared<object_server>(conn, true);
    const std::string mctpServiceName = "xyz.openbmc_project." + mctpdName;
    conn->request_name(mctpServiceName.c_str());

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Starting MCTP service: " + mctpServiceName).c_str());

    bindingPtr = getBindingPtr(*mctpdConfiguration, conn, objectServer, ioc);

    if (!bindingPtr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to create MCTP binding");
        return -1;
    }

    try
    {
        bindingPtr->setDbusName(mctpServiceName);
        bindingPtr->initializeBinding();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Exception: ") + e.what()).c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to intialize MCTP binding; exiting");
        return -1;
    }
    ioc.run();

    return 0;
}
