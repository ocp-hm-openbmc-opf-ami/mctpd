/*
// Copyright (c) 2022 Intel Corporation
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

#include "service_scanner.hpp"

#include "utils/binding_utils.hpp"
#include "utils/dbus_helper.hpp"

#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <phosphor-logging/log.hpp>
#include <unordered_map>

using MCTPServiceScanner = bridging::MCTPServiceScanner;
template <typename T1, typename T2>
using DictType = std::unordered_map<T1, T2>;
using MctpPropertiesVariantType =
    std::variant<uint16_t, int16_t, int32_t, uint32_t, bool, std::string,
                 uint8_t, std::vector<uint8_t>>;

MCTPServiceScanner::MCTPServiceScanner(
    std::shared_ptr<sdbusplus::asio::connection>& conn) :
    connection(conn)
{
    if (!connection)
    {
        throw std::invalid_argument("Expects valid asio connection");
    }
}

static mctp_eid_t
    getEIDFromPath(const sdbusplus::message::object_path& object_path)
{
    try
    {
        auto slashLoc = object_path.str.find_last_of('/');
        if (object_path.str.npos == slashLoc)
        {
            throw std::runtime_error("Invalid device path");
        }
        auto strDeviceId = object_path.str.substr(slashLoc + 1);
        return static_cast<mctp_eid_t>(std::stoi(strDeviceId));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::string("Error getting eid from ") +
                                 object_path.str + ". " + e.what());
    }
}

// Check if the DBus service reported is this process itself
static bool isSelfProcess(sdbusplus::asio::connection& connection,
                          boost::asio::yield_context yield,
                          const std::string& service)
{
    uint32_t pidSelf = getpid();

    uint32_t pid = 0;
    boost::system::error_code ec;
    pid = connection.yield_method_call<uint32_t>(
        yield, ec, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID", service.c_str());
    if (ec)
    {
        std::string errMsg =
            std::string("MCTPServiceScanner: Error getting pid for ") +
            service + ". " + ec.message();
        phosphor::logging::log<phosphor::logging::level::ERR>(errMsg.c_str());
        return false;
    }

    if (pid == pidSelf)
    {
        return true;
    }
    return false;
}

const MCTPServiceScanner::MCTPService&
    MCTPServiceScanner::getMctpServiceDetails(boost::asio::yield_context yield,
                                              const std::string& serviceName)
{
    static const std::string baseObj = "/xyz/openbmc_project/mctp";
    static const std::string baseIntf = "xyz.openbmc_project.MCTP.Base";

    auto it = cachedServices.find(serviceName);
    if (it == cachedServices.end())
    {
        MCTPService serviceDetails;
        serviceDetails.name = serviceName;
        serviceDetails.bindingID = readPropertyValue<std::string>(
            yield, *connection, serviceName, baseObj, baseIntf, "BindingID");
        serviceDetails.bindingMediumID = readPropertyValue<std::string>(
            yield, *connection, serviceName, baseObj, baseIntf,
            "BindingMediumID");
        serviceDetails.bindingMode = readPropertyValue<std::string>(
            yield, *connection, serviceName, baseObj, baseIntf, "BindingMode");
        it = cachedServices.emplace(serviceName, serviceDetails).first;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Adding to cached service : " + serviceName).c_str());
    }
    return it->second;
}

void MCTPServiceScanner::scanForEIDs(const std::string& serviceName,
                                     boost::asio::yield_context yield)
{
    try
    {
        if (isSelfProcess(*connection, yield, serviceName) ||
            !isAllowedBus(serviceName, yield))
        {
            return;
        }

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Looking for EIDs in " + serviceName).c_str());
        using ObjectTree = DictType<
            sdbusplus::message::object_path,
            DictType<std::string,
                     DictType<std::string, MctpPropertiesVariantType>>>;
        ObjectTree values;
        boost::system::error_code ec;
        values = connection->yield_method_call<ObjectTree>(
            yield, ec, serviceName, "/xyz/openbmc_project/mctp",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        if (ec)
        {
            std::string errMsg =
                std::string("MCTPServiceScanner. Error getting objects. ") +
                ec.message();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                errMsg.c_str(),
                phosphor::logging::entry("SERVICE=%s", serviceName.c_str()));
            return;
        }

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("MCTPServiceScanner found " + std::to_string(values.size()) +
             " EIDs in " + serviceName)
                .c_str());
        for (const auto& [objectPath, interfaces] : values)
        {
            if (interfaces.find("xyz.openbmc_project.MCTP.Endpoint") ==
                interfaces.end())
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    (static_cast<std::string>(objectPath) +
                     " is not an MCTP endpoint")
                        .c_str());
                return;
            }

            EndPoint ep;
            ep.eid = getEIDFromPath(objectPath);
            ep.endpointType = readPropertyValue<std::string>(
                yield, *connection, serviceName, objectPath,
                "xyz.openbmc_project.MCTP.Endpoint", "Mode");
            ep.service = getMctpServiceDetails(yield, serviceName);
            if (updatePhysicalDetails(connection, yield, objectPath,
                                      serviceName, ep))
            {
                this->onNewEid(ep, false);
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Scan device failed to get physical address details");
            }
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("EID Scan in service. ") + e.what()).c_str());
    }
}

std::vector<std::string>
    MCTPServiceScanner::getMCTPServices(boost::asio::yield_context yield)
{
    std::vector<std::string> requiredInterfaces = {
        "xyz.openbmc_project.MCTP.Base"};
    boost::system::error_code ec;
    DictType<std::string, std::vector<std::string>> services;

    // Get all available MCTP service names
    services = connection->yield_method_call<decltype(services)>(
        yield, ec, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetObject",
        "/xyz/openbmc_project/mctp", requiredInterfaces);

    std::vector<std::string> serviceNames;
    if (ec)
    {
        std::string errMsg =
            std::string("EidScanner: Error getting mctp services or no other "
                        "mctp service is present") +
            ec.message();
        phosphor::logging::log<phosphor::logging::level::ERR>(errMsg.c_str());
        return serviceNames;
    }
    for (const auto& [serviceName, interfaces] : services)
    {
        serviceNames.emplace_back(serviceName);
    }
    return serviceNames;
}

void MCTPServiceScanner::scan()
{
    auto scanTask = [this](boost::asio::yield_context yield) {
        if (!this->onNewEid)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Callback not registered for new EIds");
            return;
        }

        try
        {
            this->signalMatches.clear();
            auto onHotplugHandler =
                std::bind(&MCTPServiceScanner::onHotPluggedEid, this,
                          std::placeholders::_1);
            this->signalMatches.emplace_back(registerSignalHandler(
                *connection, onHotplugHandler,
                "org.freedesktop.DBus.ObjectManager", "InterfacesAdded",
                "/xyz/openbmc_project/mctp"));

            auto onDeviceRemoveHandler = std::bind(
                &MCTPServiceScanner::onEidRemoved, this, std::placeholders::_1);
            this->signalMatches.emplace_back(registerSignalHandler(
                *connection, onDeviceRemoveHandler,
                "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved",
                "/xyz/openbmc_project/mctp"));

            // Get all available MCTP service names
            auto mctpServices = getMCTPServices(yield);
            for (const auto& service : mctpServices)
            {
                scanForEIDs(service, yield);
            }
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                (std::string("EID Scan ") + e.what()).c_str());
        }
    };
    // If the allowed bus list is empty, then scanning for other services is not
    // required.
    if (!allowedDestBuses.empty())
    {
        boost::asio::spawn(connection->get_io_context(), scanTask);
    }
}

bool MCTPServiceScanner::isAllowedBus(const std::string& bus,
                                      boost::asio::yield_context yield)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Checking if bridging is allowed on bus " + bus).c_str());
    // If allowed bus list is empty then all serives bridging to all the
    // services is disabled by default
    if (bus.empty() || disallowedDestBuses.count(bus) > 0 ||
        allowedDestBuses.empty())
    {
        return false;
    }

    if (allowedDestBuses.count(bus) > 0)
    {
        return true;
    }

    auto mctpServices = getMCTPServices(yield);
    for (const auto& service : allowedDestBuses)
    {
        if (!service.empty() && service.front() == ':')
        {
            // Unique name already
            continue;
        }
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Checkig if " + bus + " is " + service).c_str());
        boost::system::error_code ec;
        std::string uniqueName = connection->yield_method_call<std::string>(
            yield, ec, "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetNameOwner", service.c_str());

        if (ec)
        {
            std::string errMsg = std::string("GetUniqueName unsuccesful for ") +
                                 service + ". " + ec.message();
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                errMsg.c_str());
            continue;
        }

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Unique name of " + service + " is " + uniqueName + ". Target " +
             bus)
                .c_str());

        dbusUniqueNameMap.insert_or_assign(service, uniqueName);

        if (uniqueName == bus)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Adding " + bus + " into allowed list").c_str());
            allowedDestBuses.insert(bus);
            return true;
        }
    }
    disallowedDestBuses.insert(bus);
    return false;
}

void MCTPServiceScanner::onHotPluggedEid(sdbusplus::message::message& message)
{
    if (!this->onNewEid && !this->onNewService)
    {
        return;
    }

    try
    {
        boost::asio::spawn(
            connection->get_io_context(),
            [this, message](boost::asio::yield_context yield) mutable {
                try
                {
                    DictType<std::string,
                             DictType<std::string, MctpPropertiesVariantType>>
                        values;
                    sdbusplus::message::object_path objectPath;

                    message.read(objectPath, values);
                    auto endpointIntf =
                        values.find("xyz.openbmc_project.MCTP.Endpoint");
                    auto baseIntf =
                        values.find("xyz.openbmc_project.MCTP.Base");

                    if (endpointIntf == values.end() &&
                        baseIntf == values.end())
                    {
                        return;
                    }

                    std::string serviceName = message.get_sender();
                    if (serviceName.empty())
                    {
                        return;
                    }

                    if (!isAllowedBus(serviceName, yield))
                    {
                        phosphor::logging::log<phosphor::logging::level::DEBUG>(
                            (serviceName + " is not in allowed service list")
                                .c_str());
                        return;
                    }

                    if (baseIntf != values.end() && this->onNewService)
                    {
                        phosphor::logging::log<phosphor::logging::level::DEBUG>(
                            ("New service " + serviceName).c_str());
                        if (serviceName[0] == ':')
                        {
                            auto commonNameIt = std::find_if(
                                dbusUniqueNameMap.begin(),
                                dbusUniqueNameMap.end(),
                                [&serviceName](const auto& namePair) {
                                    return namePair.second == serviceName;
                                });
                            if (commonNameIt != dbusUniqueNameMap.end())
                            {
                                phosphor::logging::log<
                                    phosphor::logging::level::DEBUG>(
                                    ("Found in dbus map " + serviceName)
                                        .c_str());
                                serviceName = commonNameIt->first;
                            }
                            phosphor::logging::log<
                                phosphor::logging::level::DEBUG>(
                                ("Service name changed to " + serviceName)
                                    .c_str());
                        }
                        this->onNewService(serviceName);
                        return;
                    }
                    if (!this->onNewEid)
                    {
                        return;
                    }
                    EndPoint ep;
                    ep.eid = getEIDFromPath(objectPath);
                    ep.endpointType =
                        std::get<std::string>(endpointIntf->second.at("Mode"));

                    if (isSelfProcess(*connection, yield, serviceName))
                    {
                        return;
                    }
                    ep.service = this->getMctpServiceDetails(
                        yield, message.get_sender());
                    if (!updatePhysicalDetails(connection, yield, objectPath,
                                               serviceName, ep))
                    {
                        phosphor::logging::log<
                            phosphor::logging::level::WARNING>(
                            "onHotPlugged failed to get physical address "
                            "details");
                    }
                    this->onNewEid(ep, true);
                }
                catch (const std::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("onHotPluggedEid. error in spawn task. ") +
                         e.what())
                            .c_str());
                }
            });
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string("onHotPluggedEid: ") + e.what()).c_str());
    }
}

void MCTPServiceScanner::onEidRemoved(sdbusplus::message::message& message)
{
    if (!this->onEidRemovedHandler)
    {
        return;
    }

    try
    {
        sdbusplus::message::object_path object_path;
        std::vector<std::string> interfaces;
        message.read(object_path, interfaces);
        auto baseIntf = std::find(interfaces.begin(), interfaces.end(),
                                  "xyz.openbmc_project.MCTP.Base");
        if (baseIntf != interfaces.end())
        {
            std::string serviceName = message.get_sender();
            // An MCTP service is going down.
            if (this->cachedServices.erase(serviceName) > 0)
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    (message.get_sender() +
                     std::string(" removed from cached services"))
                        .c_str());
            }
            if (!serviceName.empty() && serviceName.front() == ':')
            {
                // Remove unique name if it is in allow or deny list
                this->allowedDestBuses.erase(serviceName);
                this->disallowedDestBuses.erase(serviceName);
            }
        }

        auto endpointIntf = std::find(interfaces.begin(), interfaces.end(),
                                      "xyz.openbmc_project.MCTP.Endpoint");
        if (endpointIntf == interfaces.end())
        {
            return;
        }
        EndPoint ep;
        ep.eid = getEIDFromPath(object_path);
        boost::asio::spawn(
            connection->get_io_context(),
            [this, ep, message](boost::asio::yield_context yield) mutable {
                try
                {
                    std::string serviceName = message.get_sender();
                    if (isSelfProcess(*connection, yield, serviceName))
                    {
                        return;
                    }

                    if (!isAllowedBus(serviceName, yield))
                    {
                        phosphor::logging::log<phosphor::logging::level::DEBUG>(
                            (serviceName + " is not in allowed service list")
                                .c_str());
                        return;
                    }
                    // Reading from an exited service can cause exception
                    if (this->cachedServices.count(serviceName) > 0)
                    {
                        ep.service = getMctpServiceDetails(yield, serviceName);
                    }
                    else
                    {
                        ep.service.name = serviceName;
                    }
                    this->onEidRemovedHandler(ep);
                }
                catch (const std::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("onEidRemoved. error in spawn task. ") +
                         e.what())
                            .c_str());
                }
            });
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (std::string("onEidRemoved: ") + e.what()).c_str());
    }
}
