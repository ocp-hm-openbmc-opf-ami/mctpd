#pragma once

#include "utils/types.hpp"

#include <filesystem>
#include <set>
#include <string>

struct Configuration
{
    mctp_server::MctpPhysicalMediumIdentifiers mediumId;
    mctp_server::BindingModeTypes mode;
    uint8_t defaultEid;
    unsigned int reqToRespTime;
    uint8_t reqRetryCount;
    std::set<std::string> allowedBuses;
    /* Configurations for bridges to get the EID pool allocations from TopMost
     * BusOwner */
    std::unordered_map<std::string /*busName*/, uint8_t /*poolSize*/>
        downstreamEIDPoolDistribution;
    // Setting for indicating the pool size requirement to upstream bus owner
    std::uint8_t requiredEIDPoolSizeFromBO = 0;
    // Setting for the downstream bus owner's pool size
    std::uint8_t requiredEIDPoolSize = 0;
    std::string networkGUID;

    virtual ~Configuration();
};

struct SMBusConfiguration : Configuration
{
    std::set<uint8_t> eidPool;
    std::string bus;
    bool arpMasterSupport;
    uint8_t bmcSlaveAddr;
    std::set<uint8_t> supportedEndpointSlaveAddress;
    uint8_t routingIntervalSec;
    uint64_t scanInterval;

    ~SMBusConfiguration() override;
};

struct PcieConfiguration : Configuration
{
    uint16_t bdf;
    uint8_t getRoutingInterval = 0;

    ~PcieConfiguration() override;
};

struct I3CConfiguration : Configuration
{
    std::set<uint8_t> eidPool;
    uint8_t bus;
    uint8_t I3CAddress = 0;
    bool requiresCpuPidMask = true;
    uint8_t provisionalIdMask;
    uint8_t getRoutingInterval = 0;
    bool forwaredEIDPoolToEP = false;
    bool blockDiscoveryNotify = false;

    ~I3CConfiguration() override;
};

std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
    getConfiguration(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const std::string& configurationName,
                     const std::filesystem::path& configPath);
