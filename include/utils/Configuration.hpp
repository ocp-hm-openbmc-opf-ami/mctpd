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
    bool supportsBridge = false;
    uint8_t networkId;
    // Support Endpoints with OEM binding type = 0xFF behind a bridge
    bool supportOEMBindingBehindBO = false;
    // Configuration to skip devices for MCTP communications
    std::vector<std::string> skipList;
    bool isResetReachable = true;

    virtual ~Configuration();
};

struct SMBusConfiguration : Configuration
{
    std::set<uint8_t> eidPool;
    std::string bus;
    bool arpControllerSupport;
    uint8_t bmcTargetAddr;
    std::set<uint8_t> supportedEndpointTargetAddress;
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
    uint16_t provisionalIdMask;
    uint16_t getRoutingInterval = 0;
    bool forwaredEIDPoolToEP = false;
    bool blockDiscoveryNotify = false;

    ~I3CConfiguration() override;
};

std::optional<std::pair<std::string, std::unique_ptr<Configuration>>>
    getConfiguration(std::shared_ptr<sdbusplus::asio::connection> conn,
                     const std::string& configurationName);
