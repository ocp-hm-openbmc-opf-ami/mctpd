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
#include "hw/DeviceMonitor.hpp"
#include "hw/PCIeDriver.hpp"

#include <libmctp-astpcie.h>
#include <libmctp-cmds.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/PCIe/server.hpp>

using pcie_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::PCIe;

constexpr uint8_t deviceFunMask = 0xff;
constexpr uint16_t busMask = 0xff00;
constexpr uint8_t deviceFunShift = 0x8;

class PCIeBinding : public MctpBinding,
                    public hw::DeviceObserver,
                    public std::enable_shared_from_this<hw::DeviceObserver>
{
  public:
    PCIeBinding() = delete;
    PCIeBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const PcieConfiguration& conf,
                boost::asio::io_context& ioc,
                std::shared_ptr<hw::PCIeDriver>&& hw,
                std::shared_ptr<hw::DeviceMonitor>&& hwMonitor);
    ~PCIeBinding() override;
    void initializeBinding() override;

  protected:
    bool handlePrepareForEndpointDiscovery(
        mctp_eid_t destEid, void* bindingPrivate, std::vector<uint8_t>& request,
        std::vector<uint8_t>& response) override;
    bool handleEndpointDiscovery(mctp_eid_t destEid, void* bindingPrivate,
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

    void deviceReadyNotify(bool ready) override;

    void populateDeviceProperties(
        const mctp_eid_t eid,
        const std::vector<uint8_t>& bindingPrivate) override;
    uint8_t getTransportId() override;
    std::vector<uint8_t>
        getPhysicalAddress(const std::vector<uint8_t>& privateData) override;
    std::vector<uint8_t> getOwnPhysicalAddress() override;
    std::shared_ptr<hw::PCIeDriver> hw;
    std::shared_ptr<hw::DeviceMonitor> hwMonitor;

  private:
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint16_t /*bdf*/, uint8_t /*entryType*/,
                   uint8_t /*poolEid*/, uint8_t /*range*/>;
    using calledBridgeEntry_t = std::tuple<uint8_t /*eid*/, uint16_t /*bdf*/>;
    uint16_t bdf;
    uint16_t busOwnerBdf;
    std::shared_ptr<dbus_interface> pcieInterface;
    pcie_binding::DiscoveryFlags discoveredFlag{};
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    std::vector<routingTableEntry_t> routingTableResp;
    void endpointDiscoveryFlow();
    void updateRoutingTable();
    void processRoutingTableChanges(std::vector<routingTableEntry_t>& newTable,
                                    boost::asio::yield_context& yield,
                                    const std::vector<uint8_t>& prvData);
    void processBridgeEntries(std::vector<routingTableEntry_t>& rt,
                              std::vector<calledBridgeEntry_t>& calledBridges,
                              boost::asio::yield_context& yield);
    void readRoutingTable(std::vector<routingTableEntry_t>& rt,
                          std::vector<calledBridgeEntry_t>& calledBridges,
                          std::vector<uint8_t> prvData,
                          boost::asio::yield_context& yield, uint8_t eid,
                          uint16_t physAddr, long entryIndex = 0);
    uint16_t getRoutingEntryPhysAddr(
        const std::vector<uint8_t>& getRoutingTableEntryResp,
        size_t entryOffset);
    bool isEntryInRoutingTable(get_routing_table_entry* routingEntry,
                               const std::vector<routingTableEntry_t>& rt);
    bool isEndOfGetRoutingTableResp(uint8_t entryHandle,
                                    uint8_t& responseCount);
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
    bool isReceivedPrivateDataCorrect(const void* bindingPrivate) override;
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
    void changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag);
    void clearAllEids();
    void updateBridgePool(std::vector<routingTableEntry_t>& rt,
                          const uint8_t startingEidPool, const uint8_t poolSize,
                          const uint16_t physAddr);
};
