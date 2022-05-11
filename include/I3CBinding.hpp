#pragma once

#include "MCTPBinding.hpp"
#include "hw/I3CDriver.hpp"

#include <libmctp-asti3c.h>
#include <libmctp-cmds.h>

#include <boost/asio/deadline_timer.hpp>
#include <xyz/openbmc_project/MCTP/Binding/I3C/server.hpp>

using i3c_binding =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::I3C;

class I3CBinding : public MctpBinding
{
  public:
    I3CBinding() = delete;
    I3CBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const I3CConfiguration& conf,
                boost::asio::io_context& ioc,
                        const std::string& device);
    ~I3CBinding() override;
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

    void populateDeviceProperties(
        const mctp_eid_t eid,
        const std::vector<uint8_t>& bindingPrivate) override;

    std::shared_ptr<hw::I3CDriver> hw;

  private:
    using routingTableEntry_t =
        std::tuple<uint8_t /*eid*/, uint8_t /*Address*/, uint8_t /*entryType*/>;
    using calledBridgeEntry_t = std::tuple<uint8_t /*eid*/, uint8_t /*Address*/>;
    int mctpI3cFd=-1;
    uint8_t ownI3cDAA = 0; /* I3C Primary will be indicated through own address of 0 */
    uint8_t busOwnerAddress = 0;
    uint8_t bus = 0;
    std::shared_ptr<dbus_interface> i3cInterface;
    i3c_binding::DiscoveryFlags discoveredFlag{};
    boost::posix_time::seconds getRoutingInterval;
    boost::asio::deadline_timer getRoutingTableTimer;
    std::vector<routingTableEntry_t> routingTable;
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
    uint8_t getRoutingEntryPhysAddr(
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
    mctp_server::BindingModeTypes
        getBindingMode(const routingTableEntry_t& routingEntry);
    void changeDiscoveredFlag(i3c_binding::DiscoveryFlags flag);
    void onI3CDeviceChangeCallback();
};
