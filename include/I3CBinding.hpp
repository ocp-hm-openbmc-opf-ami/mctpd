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

#include "MCTPBinding.hpp"
#include "hw/I3CDriver.hpp"
#include "mctp_device.hpp"
#include "utils/utils.hpp"

#include <libmctp-asti3c.h>
#include <libmctp-cmds.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/I3C/server.hpp>

using I3CBindingServer =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::I3C;

class I3CBinding : public MctpBinding
{
  public:
    I3CBinding() = delete;
    I3CBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
               std::shared_ptr<object_server>& objServer,
               const std::string& objPath, const I3CConfiguration& conf,
               boost::asio::io_context& ioc,
               std::unique_ptr<hw::I3CDriver>&& hw);
    ~I3CBinding() override;
    void initializeBinding() override;
    void triggerDeviceDiscovery() override;

  protected:
    std::shared_ptr<hw::I3CDriver> hw;

    bool handleDiscoveryNotify(mctp_eid_t destEid, void* bindingPrivate,
                               std::vector<uint8_t>& request,
                               std::vector<uint8_t>& response) override;
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
    bool handleRoutingInfoUpdate([[maybe_unused]] mctp_eid_t destEid,
                                 [[maybe_unused]] void* bindingPrivate,
                                 [[maybe_unused]] std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response) override;
    bool handleAllocateEID(std::vector<uint8_t>& request,
                                   std::vector<uint8_t>& response) override;
    void populateDeviceProperties(
        const mctp_eid_t eid,
        const std::vector<uint8_t>& bindingPrivate) override;
    void onEIDPool() override;

  private:
    std::set<mctp_eid_t> eidTable;
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint8_t /*Address*/, uint8_t /*entryType*/>;
    using calledBridgeEntry_t =
        std::tuple<uint8_t /*eid*/, uint8_t /*Address*/>;
    int mctpI3CFd = -1;
    uint8_t ownI3cDAA =
        0; /* I3C Primary will be indicated through own address of 0 */
    uint8_t busOwnerAddress = 0;
    uint8_t bus = 0;
    std::shared_ptr<dbus_interface> i3cInterface;
    I3CBindingServer::DiscoveryFlags discoveredFlag{};
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    I3CConfiguration i3cConf{};
    std::vector<routingTableEntry_t> routingTableResp;
    bool forwaredEIDPoolToEP = false;
    bool blockDiscoveryNotify = false;
    std::vector<uint8_t>
        getPhysicalAddress(const std::vector<uint8_t>& bindingPrivate) override;
    uint8_t getTransportId() override;
    std::vector<uint8_t> getOwnPhysicalAddress() override;
    void endpointDiscoveryFlow();
    void updateRoutingTable();
    void processRoutingTableChanges(
        const std::vector<routingTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    void processBridgeEntries(std::vector<routingTableEntry_t>& rt,
                              std::vector<calledBridgeEntry_t>& calledBridges,
                              boost::asio::yield_context& yield);
    void readRoutingTable(std::vector<routingTableEntry_t>& rt,
                          std::vector<calledBridgeEntry_t>& calledBridges,
                          std::vector<uint8_t> prvData,
                          boost::asio::yield_context& yield, uint8_t eid,
                          uint8_t physAddr, long entryIndex = 0);
    std::optional<uint8_t> getRoutingEntryPhysAddr(
        const std::vector<uint8_t>& getRoutingTableEntryResp,
        size_t entryOffset);
    bool isEntryInRoutingTable(get_routing_table_entry* routingEntry,
                               const std::vector<routingTableEntry_t>& rt);
    bool isEndOfGetRoutingTableResp(uint8_t entryHandle, uint8_t responseCount);
    bool isActiveEntryBehindBridge(get_routing_table_entry* routingEntry,
                                   const std::vector<routingTableEntry_t>& rt);
    bool isEntryBridge(const routingTableEntry_t& routingEntry);
    bool isBridgeCalled(const routingTableEntry_t& routingEntry,
                        const std::vector<calledBridgeEntry_t>& calledBridges);
    bool
        allBridgesCalled(const std::vector<routingTableEntry_t>& rt,
                         const std::vector<calledBridgeEntry_t>& calledBridges);
    bool setDriverEndpointMap(const std::vector<routingTableEntry_t>& newTable);
    std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
    void changeDiscoveredFlag(I3CBindingServer::DiscoveryFlags flag);
    void onI3CDeviceChangeCallback();
    virtual bool setEIDPool(uint8_t const startEID,
                            const uint8_t poolSize) override;
    bool forwardEIDPool(boost::asio::yield_context& yield,
                        const uint8_t startEID, const uint8_t poolSize);
};
