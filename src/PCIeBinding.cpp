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

#include "PCIeBinding.hpp"

#include "utils/utils.hpp"

#include <phosphor-logging/log.hpp>

PCIeBinding::~PCIeBinding()
{
    objectServer->remove_interface(pcieInterface);
}

PCIeBinding::PCIeBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                         std::shared_ptr<object_server>& objServer,
                         const std::string& objPath,
                         const PcieConfiguration& conf,
                         boost::asio::io_context& ioc,
                         std::shared_ptr<hw::PCIeDriver>&& hwParam,
                         std::shared_ptr<hw::DeviceMonitor>&& hwMonitorParam) :
    MctpBinding(conn, objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverPcieVdm),
    hw{std::move(hwParam)}, hwMonitor{std::move(hwMonitorParam)},
    getRoutingInterval(conf.getRoutingInterval),
    getRoutingTableTimer(ioc, getRoutingInterval)
{
    pcieInterface = objServer->add_interface(objPath, pcie_binding::interface);

    try
    {
        bdf = conf.bdf;

        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
            discoveredFlag = pcie_binding::DiscoveryFlags::NotApplicable;
        else
            discoveredFlag = pcie_binding::DiscoveryFlags::Undiscovered;

        registerProperty(pcieInterface, "BDF", bdf);

        registerProperty(
            pcieInterface, "DiscoveredFlag",
            pcie_binding::convertDiscoveryFlagsToString(discoveredFlag));
        if (pcieInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }

        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            getRoutingTableTimer.async_wait(
                std::bind(&PCIeBinding::updateRoutingTable, this));
            supportOEMBindingBehindBO = conf.supportOEMBindingBehindBO;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP PCIe Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

void PCIeBinding::endpointDiscoveryFlow()
{
    struct mctp_astpcie_pkt_private pktPrv;
    pktPrv.routing = PCIE_ROUTE_TO_RC;
    pktPrv.remote_id = bdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof pktPrv);
    changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        if (!discoveryNotifyCtrlCmd(yield, prvData, MCTP_EID_NULL))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Discovery Notify failed");
        }
    });
}

mctp_server::BindingModeTypes
    PCIeBinding::getBindingMode(const routingTableEntry_t& routingEntry)
{
    if (std::get<1>(routingEntry) == busOwnerBdf)
    {
        return mctp_server::BindingModeTypes::BusOwner;
    }
    switch (std::get<2>(routingEntry))
    {
        case MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS:
        case MCTP_ROUTING_ENTRY_BRIDGE:
            return mctp_server::BindingModeTypes::Bridge;
        case MCTP_ROUTING_ENTRY_ENDPOINT:
        case MCTP_ROUTING_ENTRY_ENDPOINTS:
        default:
            return mctp_server::BindingModeTypes::Endpoint;
    }
}

uint16_t PCIeBinding::getRoutingEntryPhysAddr(
    const std::vector<uint8_t>& getRoutingTableEntryResp, size_t entryOffset)
{
    return be16toh(static_cast<uint16_t>(
        static_cast<uint16_t>(getRoutingTableEntryResp[entryOffset]) |
        (static_cast<uint16_t>(getRoutingTableEntryResp[entryOffset + 1])
         << 8)));
}

bool PCIeBinding::isEntryInRoutingTable(
    get_routing_table_entry* routingEntry,
    const std::vector<routingTableEntry_t>& rt)
{
    return std::find_if(
               rt.begin(), rt.end(), [&routingEntry](const auto& entry) {
                   const auto& [eid, endpointBdf, entryType, poolEid, range] =
                       entry;
                   return routingEntry->starting_eid == eid;
               }) != rt.end();
}

bool PCIeBinding::isActiveEntryBehindBridge(
    get_routing_table_entry* routingEntry,
    const std::vector<routingTableEntry_t>& rt)
{
    return !isEntryInRoutingTable(routingEntry, rt) &&
           routingEntry->eid_range_size == 1 &&
           routingEntry->phys_transport_binding_id == MCTP_BINDING_PCIE;
}

bool PCIeBinding::isEndOfGetRoutingTableResp(uint8_t entryHandle,
                                             uint8_t& responseCount)
{
    if (entryHandle == 0xff || responseCount == 0xff)
        return true;
    responseCount++;
    return false;
}

bool PCIeBinding::isEntryBridge(const routingTableEntry_t& routingEntry)
{
    return GET_ROUTING_ENTRY_TYPE(std::get<2>(routingEntry)) ==
               MCTP_ROUTING_ENTRY_BRIDGE ||
           GET_ROUTING_ENTRY_TYPE(std::get<2>(routingEntry)) ==
               MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS;
}

bool PCIeBinding::allBridgesCalled(
    const std::vector<routingTableEntry_t>& rt,
    const std::vector<calledBridgeEntry_t>& calledBridges)
{
    for (auto entry : rt)
    {
        if (isEntryBridge(entry) && !isBridgeCalled(entry, calledBridges))
            return false;
    }
    return true;
}

bool PCIeBinding::isBridgeCalled(
    const routingTableEntry_t& routingEntry,
    const std::vector<calledBridgeEntry_t>& calledBridges)
{
    return std::find_if(calledBridges.begin(), calledBridges.end(),
                        [&routingEntry](const auto& bridge) {
                            const auto& [eid, physAddr] = bridge;
                            return std::get<0>(routingEntry) == eid &&
                                   std::get<1>(routingEntry) == physAddr;
                        }) != calledBridges.end();
}

void PCIeBinding::updateBridgePool(std::vector<routingTableEntry_t>& rt,
                                   const uint8_t startingEidPool,
                                   const uint8_t poolSize,
                                   const uint16_t physAddr)
{
    auto it = find_if(rt.begin(), rt.end(), [&](const auto& entry) {
        const auto& [endpointEid, endpointBdf, entryType, poolEid, range] =
            entry;
        return (endpointBdf == physAddr && isEntryBridge(entry));
    });

    if (it != rt.end())
    {
        std::get<3>(*it) = startingEidPool;
        std::get<4>(*it) = poolSize;
    }
}

void PCIeBinding::readRoutingTable(
    std::vector<routingTableEntry_t>& rt,
    std::vector<calledBridgeEntry_t>& calledBridges,
    std::vector<uint8_t> prvData, boost::asio::yield_context& yield,
    uint8_t eid, uint16_t physAddr, long entryIndex)
{
    std::vector<uint8_t> getRoutingTableEntryResp = {};
    std::vector<routingTableEntry_t> tmpEndpointRoutingTable;
    uint8_t entryHandle = 0x00;
    uint8_t responseCount = 0;
    long insertIndex = entryIndex + 1;
    std::vector<routingTableEntry_t>& bridgeRoutingTable =
        [&]() -> std::vector<routingTableEntry_t>& {
        if (eid == busOwnerEid)
        {
            insertIndex--;
            return tmpEndpointRoutingTable;
        }
        else
        {
            return rt;
        }
    }();

    while (!isEndOfGetRoutingTableResp(entryHandle, responseCount))
    {
        calledBridges.push_back(std::make_tuple(eid, physAddr));

        if (!getRoutingTableCtrlCmd(yield, prvData, eid, entryHandle,
                                    getRoutingTableEntryResp))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Get Routing Table failed");
            return;
        }

        auto routingTableHdr =
            reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(
                getRoutingTableEntryResp.data());
        size_t entryOffset = sizeof(mctp_ctrl_resp_get_routing_table);

        for (uint8_t i = 0; i < routingTableHdr->number_of_entries; i++)
        {
            auto routingTableEntry = reinterpret_cast<get_routing_table_entry*>(
                getRoutingTableEntryResp.data() + entryOffset);

            entryOffset += sizeof(get_routing_table_entry);
            if (routingTableEntry->phys_transport_binding_id !=
                MCTP_BINDING_PCIE)
            {
                if (supportOEMBindingBehindBO)
                {
                    if (routingTableEntry->phys_transport_binding_id == 0xFF)
                    {
                        rt.push_back(std::make_tuple(
                            routingTableEntry->starting_eid, physAddr,
                            routingTableEntry->entry_type,
                            routingTableEntry->starting_eid,
                            routingTableEntry->eid_range_size));
                    }
                }
                entryOffset += routingTableEntry->phys_address_size;
                continue;
            }
            uint16_t entryPhysAddr =
                getRoutingEntryPhysAddr(getRoutingTableEntryResp, entryOffset);
            entryOffset += routingTableEntry->phys_address_size;

            if (eid == busOwnerEid &&
                GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                    MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS)
            {
                tmpEndpointRoutingTable.push_back(std::make_tuple(
                    routingTableEntry->starting_eid, entryPhysAddr,
                    SET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type,
                                           MCTP_ROUTING_ENTRY_BRIDGE),
                    routingTableEntry->starting_eid,
                    routingTableEntry->eid_range_size));
            }
            else if (eid == busOwnerEid &&
                     !(GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                       MCTP_ROUTING_ENTRY_ENDPOINTS))
            {
                tmpEndpointRoutingTable.push_back(std::make_tuple(
                    routingTableEntry->starting_eid, entryPhysAddr,
                    routingTableEntry->entry_type,
                    routingTableEntry->starting_eid,
                    routingTableEntry->eid_range_size));

                if (routingTableEntry->starting_eid == ownEid)
                {
                    ownPort =
                        GET_ROUTING_ENTRY_PORT(routingTableEntry->entry_type);
                }
            }
            else if (eid != busOwnerEid &&
                     isActiveEntryBehindBridge(routingTableEntry, rt))
            {
                tmpEndpointRoutingTable.push_back(std::make_tuple(
                    routingTableEntry->starting_eid, entryPhysAddr,
                    routingTableEntry->entry_type,
                    routingTableEntry->starting_eid,
                    routingTableEntry->eid_range_size));
            }
            else if (GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                     MCTP_ROUTING_ENTRY_ENDPOINTS)
            {
                updateBridgePool(
                    bridgeRoutingTable, routingTableEntry->starting_eid,
                    routingTableEntry->eid_range_size, entryPhysAddr);
            }
        }
        entryHandle = routingTableHdr->next_entry_handle;
    }

    auto it =
        find_if(bridgeRoutingTable.begin(), bridgeRoutingTable.end(),
                [&](const auto& entry) {
                    const auto& [endpointEid, endpointBdf, entryType, poolEid,
                                 range] = entry;
                    return (endpointBdf == physAddr && endpointEid == eid);
                });

    if (it != bridgeRoutingTable.end())
    {
        const auto& [endpointEid, endpointBdf, entryType, poolEid, range] = *it;

        for (auto entry = tmpEndpointRoutingTable.begin();
             entry != tmpEndpointRoutingTable.end(); entry++)
        {
            if (GET_ROUTING_ENTRY_PORT(std::get<2>(*entry)) != ownPort)
            {
                std::get<1>(*entry) = physAddr;
            }

            if ((std::get<0>(*entry) >= poolEid &&
                 std::get<0>(*entry) < poolEid + range) ||
                eid == busOwnerEid)
            {
                rt.insert(rt.begin() + insertIndex, *entry);
                insertIndex++;
            }
        }
    }
}

void PCIeBinding::processBridgeEntries(
    std::vector<routingTableEntry_t>& rt,
    std::vector<calledBridgeEntry_t>& calledBridges,
    boost::asio::yield_context& yield)
{
    std::vector<routingTableEntry_t> rtCopy = rt;

    for (auto entry = rt.begin(); entry != rt.end(); entry++)
    {
        if (!isEntryBridge(*entry) || isBridgeCalled(*entry, calledBridges))
            continue;

        mctp_astpcie_pkt_private pktPrv;
        pktPrv.routing = PCIE_ROUTE_BY_ID;
        pktPrv.remote_id = std::get<1>(*entry);
        uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
        std::vector<uint8_t> prvData = std::vector<uint8_t>(
            pktPrvPtr, pktPrvPtr + sizeof(mctp_astpcie_pkt_private));

        long entryIndex = std::distance(rt.begin(), entry);
        readRoutingTable(rtCopy, calledBridges, prvData, yield,
                         std::get<0>(*entry), std::get<1>(*entry), entryIndex);
    }
    rt = rtCopy;
}

void PCIeBinding::updateRoutingTable()
{
    struct mctp_astpcie_pkt_private pktPrv;
    getRoutingTableTimer.expires_from_now(getRoutingInterval);
    getRoutingTableTimer.async_wait(
        std::bind(&PCIeBinding::updateRoutingTable, this));

    if (discoveredFlag != pcie_binding::DiscoveryFlags::Discovered)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get Routing Table failed, undiscovered");
        return;
    }
    pktPrv.routing = PCIE_ROUTE_BY_ID;
    pktPrv.remote_id = busOwnerBdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData = std::vector<uint8_t>(
        pktPrvPtr, pktPrvPtr + sizeof(mctp_astpcie_pkt_private));

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        std::vector<routingTableEntry_t> routingTableTmp;
        std::vector<calledBridgeEntry_t> calledBridges;

        readRoutingTable(routingTableTmp, calledBridges, prvData, yield,
                         busOwnerEid, busOwnerBdf);

        while (!allBridgesCalled(routingTableTmp, calledBridges))
        {
            processBridgeEntries(routingTableTmp, calledBridges, yield);
        }

        if (routingTableTmp != routingTableResp)
        {
            if (!setDriverEndpointMap(routingTableTmp))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Failed to store routing table in KMD");
            }

            processRoutingTableChanges(routingTableTmp, yield, prvData);
            routingTableResp = routingTableTmp;
        }
    });
}

void PCIeBinding::populateDeviceProperties(
    const mctp_eid_t eid, const std::vector<uint8_t>& bindingPrivate)
{
    auto pcieBindingPvt = reinterpret_cast<const mctp_astpcie_pkt_private*>(
        bindingPrivate.data());

    std::string mctpEpObj =
        "/xyz/openbmc_project/mctp/device/" + std::to_string(eid);

    std::shared_ptr<dbus_interface> pcieIntf;
    // TODO: Replace the interface name string with sdbusplus header definition
    // when the yaml file is merged to phosphor-dbus-interfaces
    pcieIntf = objectServer->add_interface(
        mctpEpObj, "xyz.openbmc_project.Inventory.Decorator.PCIDevice");
    pcieIntf->register_property("Bus",
                                hw::bdf::getBus(pcieBindingPvt->remote_id));
    pcieIntf->register_property("Device",
                                hw::bdf::getDevice(pcieBindingPvt->remote_id));
    pcieIntf->register_property(
        "Function", hw::bdf::getFunction(pcieBindingPvt->remote_id));
    pcieIntf->initialize();
    deviceInterface.emplace(eid, std::move(pcieIntf));
}

/* Function takes new routing table, detect changes and creates or removes
 * device interfaces on dbus.
 */
void PCIeBinding::processRoutingTableChanges(
    std::vector<routingTableEntry_t>& newTable,
    boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData)
{
    /* find removed endpoints, in case entry is not present
     * in the newly read routing table remove dbus interface
     * for this device
     */
    for (auto& routingEntry : routingTableResp)
    {
        if (find(newTable.begin(), newTable.end(), routingEntry) ==
            newTable.end())
        {
            unregisterEndpoint(std::get<0>(routingEntry));
        }
    }

    /* find new endpoints, in case entry is in the newly read
     * routing table but not present in the routing table stored as
     * the class member, register new dbus device interface
     */
    auto it = newTable.begin();
    while (it != newTable.end())
    {
        auto& routingEntry = *it;
        if (find(routingTableResp.begin(), routingTableResp.end(),
                 routingEntry) == routingTableResp.end())
        {
            routingTableResp.push_back(routingEntry);
            mctp_eid_t remoteEid = std::get<0>(routingEntry);

            if (remoteEid == ownEid)
            {
                it++;
                continue;
            }

            std::vector<uint8_t> prvDataCopy = prvData;
            mctp_astpcie_pkt_private* pciePrivate =
                reinterpret_cast<mctp_astpcie_pkt_private*>(prvDataCopy.data());
            pciePrivate->remote_id = std::get<1>(routingEntry);

            /* Remove the endpoint failed to register from routing table, so it
             * will be treated as new endpoint and mctpd will try to register it
             * in next update */
            if (!registerEndpoint(yield, prvDataCopy, remoteEid,
                                  getBindingMode(routingEntry)))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Register endpoint " + std::to_string(remoteEid) +
                     " failed, removing from routing table")
                        .c_str());
                it = newTable.erase(it);
                continue;
            }

            /* Log the device info:
             * Bus - 8 bits, Device - 5 bits, Function - 3 bits
             */
            std::stringstream busHex, deviceHex, functionHex;
            busHex << std::setfill('0') << std::setw(2) << std::hex
                   << static_cast<int>(hw::bdf::getBus(pciePrivate->remote_id));
            deviceHex << std::setfill('0') << std::setw(2) << std::hex
                      << static_cast<int>(
                             hw::bdf::getDevice(pciePrivate->remote_id));
            functionHex << std::hex
                        << static_cast<int>(
                               hw::bdf::getFunction(pciePrivate->remote_id));

            std::string bus(busHex.str()), device(deviceHex.str()),
                function(functionHex.str());

            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("PCIe device " + bus + ":" + device + "." + function +
                 " registered at EID " + std::to_string(remoteEid))
                    .c_str());
        }
        it++;
    }
}

bool PCIeBinding::setDriverEndpointMap(
    const std::vector<routingTableEntry_t>& newTable)
{
    std::vector<hw::EidInfo> endpoints;

    for (const auto& [eid, busDevFunc, type, poolEid, range] : newTable)
    {
        endpoints.push_back({eid, busDevFunc});
    }

    return hw->setEndpointMap(endpoints);
}

bool PCIeBinding::isReceivedPrivateDataCorrect(const void* bindingPrivate)
{
    auto pciePrivate =
        reinterpret_cast<const mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate == nullptr || pciePrivate->remote_id == 0x00)
    {
        return false;
    }
    return true;
}

bool PCIeBinding::handlePrepareForEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        return false;
    }
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->routing != PCIE_BROADCAST_FROM_RC)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Prepare for Endpoint Discovery command can only be accepted as "
            "broadcast.");
        return false;
    }
    auto resp = castVectorToStruct<mctp_ctrl_resp_prepare_discovery>(response);

    changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    pciePrivate->routing = PCIE_ROUTE_TO_RC;
    return true;
}

bool PCIeBinding::handleEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    if (discoveredFlag == pcie_binding::DiscoveryFlags::Discovered)
    {
        return false;
    }
    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->routing != PCIE_BROADCAST_FROM_RC)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Endpoint Discovery command can only be accepted as broadcast.");
        return false;
    }
    busOwnerBdf = pciePrivate->remote_id;
    auto resp = castVectorToStruct<mctp_ctrl_resp_endpoint_discovery>(response);

    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    pciePrivate->routing = PCIE_ROUTE_TO_RC;
    return true;
}

bool PCIeBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (pciePrivate->remote_id != busOwnerBdf)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Set EID requested from non-bus owner.");
        return false;
    }
    if (!MctpBinding::handleSetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }
    auto resp = castVectorToStruct<mctp_ctrl_resp_set_eid>(response);

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Discovered);
        mctpInterface->set_property("Eid", ownEid);
    }
    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetVersionSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetMsgTypeSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    auto pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    if (!MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }

    pciePrivate->routing = PCIE_ROUTE_BY_ID;
    return true;
}

bool PCIeBinding::handleGetVdmSupport(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{

    struct mctp_ctrl_cmd_get_vdm_support* req =
        reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(request.data());

    /* Generic library API. Specialized later on. */
    struct mctp_ctrl_resp_get_vdm_support* libResp =
        castVectorToStruct<mctp_ctrl_resp_get_vdm_support>(response);

    if (mctp_ctrl_cmd_get_vdm_support(mctp, destEid, libResp) < 0)
    {
        return false;
    }

    mctp_astpcie_pkt_private* pciePrivate =
        reinterpret_cast<mctp_astpcie_pkt_private*>(bindingPrivate);
    pciePrivate->routing = PCIE_ROUTE_BY_ID;

    /* Cast to full binding specific response. */
    mctp_pci_ctrl_resp_get_vdm_support* resp =
        castVectorToStruct<mctp_pci_ctrl_resp_get_vdm_support>(response);
    uint8_t setIndex = req->vendor_id_set_selector;

    if (setIndex + 1U > vdmSetDatabase.size())
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR;
        response.resize(sizeof(mctp_ctrl_msg_hdr) +
                        sizeof(resp->completion_code));
        return true;
    }

    if (setIndex + 1U == vdmSetDatabase.size())
    {
        resp->vendor_id_set_selector = vendorIdNoMoreSets;
    }
    else
    {
        resp->vendor_id_set_selector = static_cast<uint8_t>(setIndex + 1U);
    }
    resp->vendor_id_format = vdmSetDatabase[setIndex].vendorIdFormat;
    resp->vendor_id_data = vdmSetDatabase[setIndex].vendorId;
    resp->command_set_type = vdmSetDatabase[setIndex].commandSetType;

    return true;
}

void PCIeBinding::initializeBinding()
{
    int status = 0;
    initializeMctp();
    hw->init();
    mctp_binding* binding = hw->binding();
    if (binding == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP binding init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
    status = mctp_register_bus_dynamic_eid(mctp, binding);
    if (status < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Bus registration of binding failed");
        throw std::system_error(
            std::make_error_code(static_cast<std::errc>(-status)));
    }
    if (hw->registerAsDefault() == false)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Registration as default control service failed");
        throw std::system_error(
            std::make_error_code(std::errc::operation_not_permitted));
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    // TODO. Set call back for bridging packets.
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));
    mctp_binding_set_tx_enabled(binding, true);

    if (hwMonitor->initialize() == false)
    {
        throw std::system_error(
            std::make_error_code(std::errc::function_not_supported));
    }

    hw->pollRx();

    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        endpointDiscoveryFlow();
    }

    if (hw->getBdf(bdf))
    {
        pcieInterface->set_property("BDF", bdf);
    }

    if (setMediumId(hw->getMediumId(), bindingMediumID))
    {
        mctpInterface->set_property(
            "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Incorrect medium id, BindingMediumID property not updated");
    }

    hwMonitor->observe(weak_from_this());
}

void PCIeBinding::deviceReadyNotify(bool ready)
{
    if (ready)
    {
        if (!hw->getBdf(bdf))
        {
            bdf = 0;
        }
    }
    else
    {
        bdf = 0;
        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            changeDiscoveredFlag(pcie_binding::DiscoveryFlags::Undiscovered);
        }
    }
    pcieInterface->set_property("BDF", bdf);
}

std::optional<std::vector<uint8_t>>
    PCIeBinding::getBindingPrivateData(uint8_t dstEid)
{
    mctp_astpcie_pkt_private pktPrv = {};

    pktPrv.routing = PCIE_ROUTE_BY_ID;
    auto it = find_if(routingTableResp.begin(), routingTableResp.end(),
                      [&dstEid](const auto& entry) {
                          const auto& [eid, endpointBdf, entryType, poolEid,
                                       range] = entry;
                          return eid == dstEid;
                      });
    if (it == routingTableResp.end())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Eid not found in routing table");
        return std::nullopt;
    }
    const auto& [eid, endpointBdf, entryType, poolEid, range] = *it;
    pktPrv.remote_id = endpointBdf;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    return std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));
}

void PCIeBinding::clearAllEids()
{
    for (auto& routingEntry : routingTableResp)
    {
        unregisterEndpoint(std::get<0>(routingEntry));
    }
    routingTableResp.clear();
}

void PCIeBinding::changeDiscoveredFlag(pcie_binding::DiscoveryFlags flag)
{
    discoveredFlag = flag;
    pcieInterface->set_property(
        "DiscoveredFlag", pcie_binding::convertDiscoveryFlagsToString(flag));

    if (pcie_binding::DiscoveryFlags::Discovered == flag)
    {
        getRoutingTableTimer.expires_from_now(boost::posix_time::seconds{0});
    }
    else if (pcie_binding::DiscoveryFlags::Undiscovered == flag)
    {
        clearAllEids();
    }
}

uint8_t PCIeBinding::getTransportId()
{
    return MCTP_BINDING_PCIE;
}

std::vector<uint8_t>
    PCIeBinding::getPhysicalAddress(const std::vector<uint8_t>& privateData)
{
    auto pcieBindingPvt =
        reinterpret_cast<const mctp_astpcie_pkt_private*>(privateData.data());
    return std::vector<uint8_t>{
        static_cast<uint8_t>(pcieBindingPvt->remote_id & deviceFunMask),
        static_cast<uint8_t>((pcieBindingPvt->remote_id & busMask) >>
                             deviceFunShift)};
}

std::vector<uint8_t> PCIeBinding::getOwnPhysicalAddress()
{
    return std::vector<uint8_t>{
        static_cast<uint8_t>(bdf & deviceFunMask),
        static_cast<uint8_t>((bdf & busMask) >> deviceFunShift)};
}
