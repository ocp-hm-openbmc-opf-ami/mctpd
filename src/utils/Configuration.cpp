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

#include "utils/Configuration.hpp"

#include "utils/types.hpp"

#include <boost/algorithm/string.hpp>
#include <fstream>
#include <memory>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <sdbusplus/asio/connection.hpp>
#include <string>
#include <variant>
#include <vector>

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>,
                 std::vector<std::string>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string mctpTypeName =
    "xyz.openbmc_project.Configuration.MctpConfiguration";

static const std::string boardPathNamespace =
    "/xyz/openbmc_project/inventory/system/board";

static const std::unordered_map<std::string, mctp_server::BindingModeTypes>
    stringToBindingModeMap = {
        {"busowner", mctp_server::BindingModeTypes::BusOwner},
        {"BusOwner", mctp_server::BindingModeTypes::BusOwner},
        {"endpoint", mctp_server::BindingModeTypes::Endpoint},
        {"Endpoint", mctp_server::BindingModeTypes::Endpoint},
        {"bridge", mctp_server::BindingModeTypes::Bridge},
        {"Bridge", mctp_server::BindingModeTypes::Bridge}};

static const std::unordered_map<std::string,
                                mctp_server::MctpPhysicalMediumIdentifiers>
    stringToMediumID = {
        {"Smbus", mctp_server::MctpPhysicalMediumIdentifiers::Smbus},
        {"SmbusI2c", mctp_server::MctpPhysicalMediumIdentifiers::SmbusI2c},
        {"I2cCompatible",
         mctp_server::MctpPhysicalMediumIdentifiers::I2cCompatible},
        {"Smbus3OrI2c400khzCompatible",
         mctp_server::MctpPhysicalMediumIdentifiers::
             Smbus3OrI2c400khzCompatible},
        {"Smbus3OrI2c1MhzCompatible",
         mctp_server::MctpPhysicalMediumIdentifiers::Smbus3OrI2c1MhzCompatible},
        {"I2c3Mhz4Compatible",
         mctp_server::MctpPhysicalMediumIdentifiers::I2c3Mhz4Compatible},
        {"Pcie11", mctp_server::MctpPhysicalMediumIdentifiers::Pcie11},
        {"Pcie2", mctp_server::MctpPhysicalMediumIdentifiers::Pcie2},
        {"Pcie21", mctp_server::MctpPhysicalMediumIdentifiers::Pcie21},
        {"Pcie3", mctp_server::MctpPhysicalMediumIdentifiers::Pcie3},
        {"Pcie4", mctp_server::MctpPhysicalMediumIdentifiers::Pcie4},
        {"Pcie5", mctp_server::MctpPhysicalMediumIdentifiers::Pcie5},
        {"PciCompatible",
         mctp_server::MctpPhysicalMediumIdentifiers::PciCompatible},
        {"Usb11Compatible",
         mctp_server::MctpPhysicalMediumIdentifiers::Usb11Compatible},
        {"Usb20Compatible",
         mctp_server::MctpPhysicalMediumIdentifiers::Usb20Compatible},
        {"Usb30Compatible",
         mctp_server::MctpPhysicalMediumIdentifiers::Usb30Compatible},
        {"NcSiOverRbt",
         mctp_server::MctpPhysicalMediumIdentifiers::NcSiOverRbt},
        {"KcsLegacy", mctp_server::MctpPhysicalMediumIdentifiers::KcsLegacy},
        {"KcsPci", mctp_server::MctpPhysicalMediumIdentifiers::KcsPci},
        {"SerialHostLegacy",
         mctp_server::MctpPhysicalMediumIdentifiers::SerialHostLegacy},
        {"SerialHostPci",
         mctp_server::MctpPhysicalMediumIdentifiers::SerialHostPci},
        {"AsynchronousSerial",
         mctp_server::MctpPhysicalMediumIdentifiers::AsynchronousSerial},
        {"I3cSDR", mctp_server::MctpPhysicalMediumIdentifiers::I3cSDR},
        {"I3cHDRDDR", mctp_server::MctpPhysicalMediumIdentifiers::I3cHDRDDR}};

template <typename T>
static bool getField(const ConfigurationMap& configuration,
                     const std::string& fieldName, T& value)
{
    auto it = configuration.find(fieldName);
    if (it != configuration.end())
    {
        const T* ptrValue = std::get_if<T>(&it->second);
        if (ptrValue != nullptr)
        {
            value = *ptrValue;
            return true;
        }
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        ("Missing configuration field " + fieldName).c_str());
    return false;
}

template <typename T>
std::set<std::string> getAllowedBuses(const T& map)
{
    std::vector<std::string> allowedBuses;
    if (!getField(map, "AllowedBuses", allowedBuses))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Allowed buses list not found in MCTPD configuration. Everything "
            "will be white listed");
    }
    phosphor::logging::log<phosphor::logging::level::WARNING>(
        (std::string("Allowed buses in config : ") +
         std::to_string(allowedBuses.size()))
            .c_str());
    return std::set<std::string>(allowedBuses.begin(), allowedBuses.end());
}

template <typename T>
uint8_t getNetworkID(const T& map)
{
    uint64_t networkId = 0;
    if (!getField(map, "NetworkID", networkId))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Network ID not found in MCTP configuration. Assuming EIDs wont "
            "overlap");
        networkId = 0;
    }
    return static_cast<uint8_t>(networkId);
}

template <typename T>
static std::optional<SMBusConfiguration> getSMBusConfiguration(const T& map)
{
    std::string physicalMediumID;
    std::string role;
    uint64_t defaultEID = 0;
    std::vector<uint64_t> eidPool;
    std::string bus;
    bool arpOwnerSupport = false;
    uint64_t bmcReceiverAddress = 0;
    uint64_t reqToRespTimeMs = 0;
    uint64_t reqRetryCount = 0;
    uint64_t scanInterval = 0;
    std::vector<std::string> skipSlotName;
    std::vector<uint64_t> supportedEndpointTargetAddress;
    std::vector<uint64_t> ignoredEndpointTargetAddress;

    if (!getField(map, "PhysicalMediumID", physicalMediumID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Role", role) && !getField(map, "role", role))
    {
        return std::nullopt;
    }

    getField(map, "SkipSlot", skipSlotName);

    if (!getField(map, "DefaultEID", defaultEID) &&
        !getField(map, "default-eid", defaultEID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Bus", bus) && !getField(map, "bus", bus))
    {
        return std::nullopt;
    }

    if (!getField(map, "ARPOwnerSupport", arpOwnerSupport) &&
        !getField(map, "ARPControllerSupport", arpOwnerSupport))
    {
        return std::nullopt;
    }

    if (!getField(map, "BMCReceiverAddress", bmcReceiverAddress) &&
        !getField(map, "BMCTargetAddress", bmcReceiverAddress))
    {
        return std::nullopt;
    }

    if (!getField(map, "ReqToRespTimeMs", reqToRespTimeMs) ||
        !getField(map, "ReqRetryCount", reqRetryCount))
    {
        return std::nullopt;
    }

    if (!getField(map, "ScanInterval", scanInterval) || !scanInterval)
    {
        // Set default 10min interval if not specified or invalid
        scanInterval = 600;
    }

    const auto mode = stringToBindingModeMap.at(role);
    if (mode == mctp_server::BindingModeTypes::BusOwner &&
        !getField(map, "EIDPool", eidPool) &&
        !getField(map, "eid-pool", eidPool))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Role is set to BusOwner but EIDPool is missing");
        return std::nullopt;
    }

    if (!getField(map, "SupportedEndpointTargetAddress",
                  supportedEndpointTargetAddress))
    {
        constexpr uint8_t startAddr = 0x08;
        constexpr uint8_t endAddr = 0x78;
        supportedEndpointTargetAddress.reserve(endAddr - startAddr);
        for (uint8_t it = startAddr; it < endAddr; it++)
        {
            supportedEndpointTargetAddress.push_back(it);
        }
    }

    if (!getField(map, "IgnoredEndpointTargetAddress",
                  ignoredEndpointTargetAddress))
    {
        ignoredEndpointTargetAddress = {};
    }

    auto endpointTargetAddress =
        std::set<uint8_t>(supportedEndpointTargetAddress.begin(),
                          supportedEndpointTargetAddress.end());

    // Remove address in ignored list
    for (uint64_t it : ignoredEndpointTargetAddress)
    {
        endpointTargetAddress.erase(static_cast<uint8_t>(it));
    }

    SMBusConfiguration config;
    config.mediumId = stringToMediumID.at(physicalMediumID);
    config.mode = mode;
    config.defaultEid = static_cast<uint8_t>(defaultEID);
    if (mode == mctp_server::BindingModeTypes::BusOwner)
    {
        config.eidPool = std::set<uint8_t>(eidPool.begin(), eidPool.end());
    }
    config.supportedEndpointTargetAddress = endpointTargetAddress;
    config.bus = bus;
    config.arpControllerSupport = arpOwnerSupport;
    config.bmcTargetAddr = static_cast<uint8_t>(bmcReceiverAddress);
    config.reqToRespTime = static_cast<unsigned int>(reqToRespTimeMs);
    config.reqRetryCount = static_cast<uint8_t>(reqRetryCount);
    config.scanInterval = scanInterval;
    config.allowedBuses = getAllowedBuses(map);
    config.networkId = getNetworkID(map);
    config.skipList = skipSlotName;

    return config;
}

template <typename T>
static std::optional<I3CConfiguration> getI3CConfiguration(const T& map)
{
    std::string physicalMediumID;
    std::string role;
    uint64_t defaultEID = 0;
    std::vector<uint64_t> eidPool;
    uint64_t bus;
    uint64_t I3CAddress = 0;
    uint64_t reqToRespTimeMs = 0;
    uint64_t reqRetryCount = 0;
    bool requiresCpuPidMask = false;
    bool supportsBridge = false;
    uint64_t provisionalIdMask = 0;
    uint64_t getRoutingInterval = 0;
    uint64_t requiredEIDPoolSize = 0;
    uint64_t requiredEIDPoolSizeFromBO = 0;
    bool forwaredEIDPoolToEP = false;
    bool blockDicoveryNotify = false;

    if (!getField(map, "PhysicalMediumID", physicalMediumID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Role", role))
    {
        return std::nullopt;
    }

    if (!getField(map, "DefaultEID", defaultEID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Bus", bus))
    {
        return std::nullopt;
    }

    if (!getField(map, "ReqToRespTimeMs", reqToRespTimeMs) ||
        !getField(map, "ReqRetryCount", reqRetryCount))
    {
        return std::nullopt;
    }

    const auto mode = stringToBindingModeMap.at(role);
    if (mode == mctp_server::BindingModeTypes::BusOwner &&
        !getField(map, "EIDPool", eidPool))
    {
        // Check if a topmost bus owner can set the EID pool
        if (!getField(map, "RequiredEIDPoolSize", requiredEIDPoolSize))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Role is set to BusOwner but EIDPool is missing");
            return std::nullopt;
        }
    }

    if (mode == mctp_server::BindingModeTypes::Endpoint &&
        !getField(map, "RequiredEIDPoolFromBO", requiredEIDPoolSizeFromBO))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Endpoint will not ask for EID Pool from Bus Owner");
    }

    if (mode != mctp_server::BindingModeTypes::BusOwner &&
        !getField(map, "GetRoutingInterval", getRoutingInterval))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Role is not BusOwner but Get Routing update interval is missing");
        return std::nullopt;
    }

    if (getField(map, "RequiresCpuPidMask", requiresCpuPidMask))
    {
        if (requiresCpuPidMask &&
            !getField(map, "ProvisionalIdMask", provisionalIdMask))
        {
            // Requires CPU PID mask was set to true but none was provided
            return std::nullopt;
        }
    }

    if (!getField(map, "I3CAddress", I3CAddress))
    {
        // We are in I3C primary role. DSP0233 v1.0.0 Section 5.6 mentions that
        // I3C primary's address
        // be set to 0
        I3CAddress = 0;
    }
    getField(map, "SupportsBridge", supportsBridge);

    getField(map, "ForwardEIDPool", forwaredEIDPoolToEP);
    getField(map, "BlockDiscoveryNotify", blockDicoveryNotify);

    I3CConfiguration config;

    //Learn about OEM binding endpoints behind busOwner
    if (mode != mctp_server::BindingModeTypes::BusOwner)
    {
        config.supportOEMBindingBehindBO = true;
    }
    config.mediumId = stringToMediumID.at(physicalMediumID);
    config.mode = mode;
    config.defaultEid = static_cast<uint8_t>(defaultEID);
    if ((mode == mctp_server::BindingModeTypes::BusOwner) &&
        (requiredEIDPoolSize == 0))
    {
        config.eidPool = std::set<uint8_t>(eidPool.begin(), eidPool.end());
    }

    config.bus = static_cast<uint8_t>(bus);
    config.reqToRespTime = static_cast<unsigned int>(reqToRespTimeMs);
    config.reqRetryCount = static_cast<uint8_t>(reqRetryCount);
    config.requiresCpuPidMask = requiresCpuPidMask;
    config.supportsBridge = supportsBridge;
    config.provisionalIdMask = static_cast<uint8_t>(provisionalIdMask);
    config.I3CAddress = static_cast<uint8_t>(I3CAddress);
    config.getRoutingInterval = static_cast<uint16_t>(getRoutingInterval);
    config.allowedBuses = getAllowedBuses(map);
    config.requiredEIDPoolSizeFromBO =
        static_cast<uint8_t>(requiredEIDPoolSizeFromBO);
    config.requiredEIDPoolSize = static_cast<uint8_t>(requiredEIDPoolSize);
    config.forwaredEIDPoolToEP = forwaredEIDPoolToEP;
    config.blockDiscoveryNotify = blockDicoveryNotify;
    config.networkId = getNetworkID(map);

    return config;
}

template <typename T>
static std::optional<PcieConfiguration> getPcieConfiguration(const T& map)
{
    std::string physicalMediumID;
    std::string role;
    uint64_t defaultEID;
    uint64_t bdf;
    uint64_t reqToRespTimeMs;
    uint64_t reqRetryCount;
    uint64_t getRoutingInterval;

    if (!getField(map, "PhysicalMediumID", physicalMediumID))
    {
        return std::nullopt;
    }

    if (!getField(map, "Role", role) && !getField(map, "role", role))
    {
        return std::nullopt;
    }

    if (!getField(map, "DefaultEID", defaultEID) &&
        !getField(map, "default-eid", defaultEID))
    {
        return std::nullopt;
    }

    if (!getField(map, "BDF", bdf) && !getField(map, "bdf", bdf))
    {
        return std::nullopt;
    }

    if (!getField(map, "ReqToRespTimeMs", reqToRespTimeMs) ||
        !getField(map, "ReqRetryCount", reqRetryCount))
    {
        return std::nullopt;
    }

    const auto mode = stringToBindingModeMap.at(role);
    if (mode != mctp_server::BindingModeTypes::BusOwner &&
        !getField(map, "GetRoutingInterval", getRoutingInterval))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Role is not BusOwner but Get Routing update interval is missing");
        return std::nullopt;
    }

    PcieConfiguration config;
    config.mediumId = stringToMediumID.at(physicalMediumID);
    config.mode = stringToBindingModeMap.at(role);
    config.defaultEid = static_cast<uint8_t>(defaultEID);
    config.bdf = static_cast<uint16_t>(bdf);
    config.reqToRespTime = static_cast<unsigned int>(reqToRespTimeMs);
    config.reqRetryCount = static_cast<uint8_t>(reqRetryCount);
    if (mode != mctp_server::BindingModeTypes::BusOwner)
    {
        config.getRoutingInterval = static_cast<uint8_t>(getRoutingInterval);
        config.supportOEMBindingBehindBO = true;
    }
    config.networkId = getNetworkID(map);

    return config;
}

static ConfigurationMap
    getConfigurationMap(std::shared_ptr<sdbusplus::asio::connection> conn,
                        const std::string& configurationPath)
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.EntityManager", configurationPath.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    method_call.append(mctpTypeName);

    // Note: This is a blocking call.
    // However, there is nothing to do until the configuration is retrieved.
    auto reply = conn->call(method_call);
    ConfigurationMap map;
    reply.read(map);
    return map;
}

static ConfigurationMap getEIDPoolConfigurationMap(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationPath)
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.EntityManager", configurationPath.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    method_call.append("xyz.openbmc_project.Configuration.MctpConfiguration."
                       "EIDPoolDistribution");

    // Note: This is a blocking call.
    // However, there is nothing to do until the configuration is retrieved.
    auto reply = conn->call(method_call);
    ConfigurationMap map;
    reply.read(map);
    return map;
}

static std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
    getConfigurationFromEntityManager(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        const std::string& configurationName)
{
    const std::string relativePath =
        boost::algorithm::replace_all_copy(configurationName, "_2f", "/");
    if (relativePath == configurationName)
    {
        return std::nullopt;
    }

    const std::string objectPath = boardPathNamespace + "/" + relativePath;
    ConfigurationMap map;
    try
    {
        map = getConfigurationMap(conn, objectPath);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error retrieving configuration from EntityManager");
        return std::nullopt;
    }

    std::string name;
    if (!getField(map, "Name", name))
    {
        return std::nullopt;
    }

    std::string bindingType;
    if (!getField(map, "TransportBindingType", bindingType) &&
        !getField(map, "BindingType", bindingType))
    {
        return std::nullopt;
    }

    std::unique_ptr<Configuration> configuration;
    if (bindingType == "MctpSMBus")
    {
        if (auto optConfig = getSMBusConfiguration(map))
        {
            configuration =
                std::make_unique<SMBusConfiguration>(std::move(*optConfig));
        }
    }
    else if (bindingType == "MctpPCIe")
    {
        if (auto optConfig = getPcieConfiguration(map))
        {
            configuration =
                std::make_unique<PcieConfiguration>(std::move(*optConfig));
        }
    }

    else if (bindingType == "MctpI3C")
    {
        if (auto optConfig = getI3CConfiguration(map))
        {
            configuration =
                std::make_unique<I3CConfiguration>(std::move(*optConfig));
        }
    }

    if (!configuration)
    {
        return std::nullopt;
    }

    /* xyz.openbmc_project.Configuration.MctpConfiguration.EIDPoolDistribution
    holds the EID pool configuration for the bus owners on the bridge */
    ConfigurationMap eidPoolDistribution;
    if (configuration->requiredEIDPoolSizeFromBO > 0)
    {
        try
        {
            eidPoolDistribution = getEIDPoolConfigurationMap(conn, objectPath);

            for (auto& [busName, requiredPool] : eidPoolDistribution)
            {
                configuration->downstreamEIDPoolDistribution.insert_or_assign(
                    ("xyz.openbmc_project." + busName),
                    static_cast<uint8_t>(std::get<uint64_t>(requiredPool)));
            }
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error retrieving EID Pool distributions");
            return std::nullopt;
        }
    }

    const std::regex illegal_name_regex("[^A-Za-z0-9_.]");
    std::regex_replace(name.begin(), name.begin(), name.end(),
                       illegal_name_regex, "_");
    return std::make_pair(name, std::move(configuration));
}

std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
    getConfiguration(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const std::string& configurationName)
{
    auto configurationPair =
        getConfigurationFromEntityManager(conn, configurationName);
    if (!configurationPair)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in getting configuration");
    }
    return configurationPair;
}

Configuration::~Configuration()
{
}

SMBusConfiguration::~SMBusConfiguration()
{
}

PcieConfiguration::~PcieConfiguration()
{
}

I3CConfiguration::~I3CConfiguration()
{
}
