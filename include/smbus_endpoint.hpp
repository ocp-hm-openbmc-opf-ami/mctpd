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

#pragma once

#include "smbus_device.hpp"

enum class DiscoveryFlags : uint8_t
{
    kNotApplicable = 0,
    kUnDiscovered,
    kDiscovered,
};

class SMBusEndpoint : public SMBusDevice
{
  public:
    SMBusEndpoint(std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<object_server>& objServer,
                  const std::string& objPath, const SMBusConfiguration& conf,
                  boost::asio::io_context& ioc);
    SMBusEndpoint() = delete;
    ~SMBusEndpoint() = default;

  protected:
    uint8_t smbusRoutingInterval;
    DiscoveryFlags discoveredFlag;

    std::string convertToString(DiscoveryFlags flag);
    bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleGetVersionSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetMsgTypeSupport(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleGetVdmSupport(mctp_eid_t endpointEid, void* bindingPrivate,
                             std::vector<uint8_t>& request,
                             std::vector<uint8_t>& response) override;
    bool handleEndpointDiscovery(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleResolveEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                 std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response) override;
    bool handleDiscoveryNotify(mctp_eid_t destEid, void* bindingPrivate,
                               std::vector<uint8_t>& request,
                               std::vector<uint8_t>& response) override;

  private:
    std::unique_ptr<boost::asio::steady_timer> smbusRoutingTableTimer;

    void updateRoutingTable();
    void updateDiscoveredFlag(DiscoveryFlags flag);
};
