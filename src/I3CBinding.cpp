#include "I3CBinding.hpp"
#include "hw/aspeed/I3CDriver.hpp"

#include <phosphor-logging/log.hpp>

I3CBinding::~I3CBinding()
{
    objectServer->remove_interface(i3cInterface);
}

I3CBinding::I3CBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                        std::shared_ptr<object_server>& objServer,
                        const std::string& objPath,
                        const I3CConfiguration& conf,
                        boost::asio::io_context& ioc,
                        const std::string& device) :
    MctpBinding(conn, objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverI3c),
    getRoutingInterval(conf.getRoutingInterval),
    getRoutingTableTimer(ioc, getRoutingInterval)
{
    int fd = open(device.c_str(), O_RDWR);
    this->mctpI3cFd = fd;
    hw = std::make_unique<hw::aspeed::I3CDriver>(ioc, fd);

    i3cInterface = objServer->add_interface(objPath, i3c_binding::interface);

    try
    {
        bus = 0;
        
        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
            discoveredFlag = i3c_binding::DiscoveryFlags::NotApplicable;
        else
            discoveredFlag = i3c_binding::DiscoveryFlags::Undiscovered;

        registerProperty(i3cInterface, "Address", ownI3cDAA);

        registerProperty(
            i3cInterface, "DiscoveredFlag",
            i3c_binding::convertDiscoveryFlagsToString(discoveredFlag));
        if (i3cInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }

        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            getRoutingTableTimer.async_wait(
                std::bind(&I3CBinding::updateRoutingTable, this));
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP I3C Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

void I3CBinding::onI3CDeviceChangeCallback()
{

}

void I3CBinding::endpointDiscoveryFlow()
{
    struct mctp_asti3c_pkt_private pktPrv;
    pktPrv.fd = mctpI3cFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));
    changeDiscoveredFlag(i3c_binding::DiscoveryFlags::Undiscovered);

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        if (!discoveryNotifyCtrlCmd(yield, prvData, MCTP_EID_NULL))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Discovery Notify failed");
        }
    });
}

mctp_server::BindingModeTypes
    I3CBinding::getBindingMode(const routingTableEntry_t& routingEntry)
{
    if (std::get<1>(routingEntry) == busOwnerAddress)
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

uint8_t I3CBinding::getRoutingEntryPhysAddr(
    const std::vector<uint8_t>& getRoutingTableEntryResp, size_t entryOffset)
{
    return getRoutingTableEntryResp[entryOffset];
}

bool I3CBinding::isEntryInRoutingTable(
    get_routing_table_entry* routingEntry,
    const std::vector<routingTableEntry_t>& rt)
{
    return std::find_if(rt.begin(), rt.end(),
                        [&routingEntry](const auto& entry) {
                            const auto& [eid, endpointAddress, entryType] = entry;
                            return routingEntry->starting_eid == eid;
                        }) != rt.end();
}

bool I3CBinding::isActiveEntryBehindBridge(
    get_routing_table_entry* routingEntry,
    const std::vector<routingTableEntry_t>& rt)
{
    return !isEntryInRoutingTable(routingEntry, rt) &&
           routingEntry->eid_range_size == 1 &&
           routingEntry->phys_transport_binding_id == MCTP_BINDING_I3C;
}

bool I3CBinding::isEndOfGetRoutingTableResp(uint8_t entryHandle,
                                             uint8_t& responseCount)
{
    if (entryHandle == 0xff || responseCount == 0xff)
        return true;
    responseCount++;
    return false;
}

bool I3CBinding::isEntryBridge(const routingTableEntry_t& routingEntry)
{
    return GET_ROUTING_ENTRY_TYPE(std::get<2>(routingEntry)) ==
               MCTP_ROUTING_ENTRY_BRIDGE ||
           GET_ROUTING_ENTRY_TYPE(std::get<2>(routingEntry)) ==
               MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS;
}

bool I3CBinding::allBridgesCalled(
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

bool I3CBinding::isBridgeCalled(
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

void I3CBinding::readRoutingTable(
    std::vector<routingTableEntry_t>& rt,
    std::vector<calledBridgeEntry_t>& calledBridges,
    std::vector<uint8_t> prvData, boost::asio::yield_context& yield,
    uint8_t eid, uint8_t physAddr, long entryIndex)
{
    std::vector<uint8_t> getRoutingTableEntryResp = {};
    uint8_t entryHandle = 0x00;
    uint8_t responseCount = 0;
    long insertIndex = entryIndex + 1;

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
                MCTP_BINDING_I3C)
            {
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
                rt.push_back(std::make_tuple(
                    routingTableEntry->starting_eid, entryPhysAddr,
                    SET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type,
                                           MCTP_ROUTING_ENTRY_BRIDGE)));
            }
            else if (eid == busOwnerEid &&
                     !(GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                       MCTP_ROUTING_ENTRY_ENDPOINTS))
            {
                rt.push_back(std::make_tuple(routingTableEntry->starting_eid,
                                             entryPhysAddr,
                                             routingTableEntry->entry_type));
            }
            else if (eid != busOwnerEid &&
                     isActiveEntryBehindBridge(routingTableEntry, rt))
            {
                rt.insert(rt.begin() + insertIndex,
                          std::make_tuple(routingTableEntry->starting_eid,
                                          physAddr,
                                          routingTableEntry->entry_type));
                insertIndex++;
            }
        }
        entryHandle = routingTableHdr->next_entry_handle;
    }
}

void I3CBinding::processBridgeEntries(
    std::vector<routingTableEntry_t>& rt,
    std::vector<calledBridgeEntry_t>& calledBridges,
    boost::asio::yield_context& yield)
{
    std::vector<routingTableEntry_t> rtCopy = rt;

    for (auto entry = rt.begin(); entry != rt.end(); entry++)
    {
        if (!isEntryBridge(*entry) || isBridgeCalled(*entry, calledBridges))
            continue;

        mctp_asti3c_pkt_private pktPrv;
        pktPrv.fd = mctpI3cFd;
        uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
        std::vector<uint8_t> prvData = std::vector<uint8_t>(
            pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

        long entryIndex = std::distance(rt.begin(), entry);
        readRoutingTable(rtCopy, calledBridges, prvData, yield,
                         std::get<0>(*entry), std::get<1>(*entry), entryIndex);
    }
    rt = rtCopy;
}

void I3CBinding::updateRoutingTable()
{
    struct mctp_asti3c_pkt_private pktPrv;
    getRoutingTableTimer.expires_from_now(getRoutingInterval);
    getRoutingTableTimer.async_wait(
        std::bind(&I3CBinding::updateRoutingTable, this));

    if (discoveredFlag != i3c_binding::DiscoveryFlags::Discovered)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get Routing Table failed, undiscovered");
        return;
    }
    pktPrv.fd = mctpI3cFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData = std::vector<uint8_t>(
        pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        std::vector<routingTableEntry_t> routingTableTmp;
        std::vector<calledBridgeEntry_t> calledBridges;

        readRoutingTable(routingTableTmp, calledBridges, prvData, yield,
                         busOwnerEid, ownI3cDAA);

        while (!allBridgesCalled(routingTableTmp, calledBridges))
        {
            processBridgeEntries(routingTableTmp, calledBridges, yield);
        }

        if (routingTableTmp != routingTable)
        {
            processRoutingTableChanges(routingTableTmp, yield, prvData);
            routingTable = routingTableTmp;
        }
    });
}

void I3CBinding::populateDeviceProperties(
    const mctp_eid_t eid, const std::vector<uint8_t>& /*bindingPrivate*/)
{
    std::string mctpEpObj =
        "/xyz/openbmc_project/mctp/device/" + std::to_string(eid);

    std::shared_ptr<dbus_interface> i3cIntf;
    // TODO: Read symlinks and find the DAA getDAAfromFd()
    i3cIntf = objectServer->add_interface(
        mctpEpObj, "xyz.openbmc_project.Inventory.Decorator.I3CDevice");
    i3cIntf->register_property("Bus", bus);
    i3cIntf->register_property("Address", ownI3cDAA);
    i3cIntf->initialize();
    deviceInterface.emplace(eid, std::move(i3cIntf));
}

/* Function takes new routing table, detect changes and creates or removes
 * device interfaces on dbus.
 */
void I3CBinding::processRoutingTableChanges(
    const std::vector<routingTableEntry_t>& newTable,
    boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData)
{
    /* find removed endpoints, in case entry is not present
     * in the newly read routing table remove dbus interface
     * for this device
     */
    for (auto& routingEntry : routingTable)
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
    for (auto& routingEntry : newTable)
    {
        if (find(routingTable.begin(), routingTable.end(), routingEntry) ==
            routingTable.end())
        {
            mctp_eid_t remoteEid = std::get<0>(routingEntry);

            if (remoteEid == ownEid)
            {
                continue;
            }

            std::vector<uint8_t> prvDataCopy = prvData;
            registerEndpoint(yield, prvDataCopy, remoteEid,
                             getBindingMode(routingEntry));


            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("I3C device at bus " + std::to_string(bus) + " and address " + std::to_string(ownI3cDAA) +
                 " registered at EID " + std::to_string(remoteEid))
                    .c_str());
        }
    }
}

bool I3CBinding::handlePrepareForEndpointDiscovery(
    mctp_eid_t, void* /*bindingPrivate*/, std::vector<uint8_t>&,
    std::vector<uint8_t>& response)
{
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        return false;
    }
    
    response.resize(sizeof(mctp_ctrl_resp_prepare_discovery));
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_prepare_discovery*>(response.data());

    changeDiscoveredFlag(i3c_binding::DiscoveryFlags::Undiscovered);
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    return true;
}

bool I3CBinding::handleEndpointDiscovery(mctp_eid_t, void* /*bindingPrivate*/,
                                          std::vector<uint8_t>&,
                                          std::vector<uint8_t>& response)
{
    if (discoveredFlag == i3c_binding::DiscoveryFlags::Discovered)
    {
        return false;
    }
    
    response.resize(sizeof(mctp_ctrl_resp_endpoint_discovery));
    auto resp =
        reinterpret_cast<mctp_ctrl_resp_endpoint_discovery*>(response.data());

    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    return true;
}

bool I3CBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }
    return true;
}

bool I3CBinding::handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleSetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }
    response.resize(sizeof(mctp_ctrl_resp_set_eid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_set_eid*>(response.data());

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        changeDiscoveredFlag(i3c_binding::DiscoveryFlags::Discovered);
        mctpInterface->set_property("Eid", ownEid);
    }
    return true;
}

bool I3CBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetVersionSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }
    return true;
}

bool I3CBinding::handleGetMsgTypeSupport(mctp_eid_t destEid,
                                          void* bindingPrivate,
                                          std::vector<uint8_t>& request,
                                          std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate, request,
                                              response))
    {
        return false;
    }
    return true;
}

bool I3CBinding::handleGetVdmSupport(mctp_eid_t destEid, void* /*bindingPrivate*/,
                                      std::vector<uint8_t>& request,
                                      std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_pci_ctrl_resp_get_vdm_support));

    struct mctp_ctrl_cmd_get_vdm_support* req =
        reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(request.data());

    /* Generic library API. Specialized later on. */
    struct mctp_ctrl_resp_get_vdm_support* libResp =
        reinterpret_cast<struct mctp_ctrl_resp_get_vdm_support*>(
            response.data());

    if (mctp_ctrl_cmd_get_vdm_support(mctp, destEid, libResp) < 0)
    {
        return false;
    }

    /* Cast to full binding specific response. */
    mctp_pci_ctrl_resp_get_vdm_support* resp =
        reinterpret_cast<mctp_pci_ctrl_resp_get_vdm_support*>(response.data());
    uint8_t setIndex = req->vendor_id_set_selector;

    if (setIndex + 1U > vdmSetDatabase.size())
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
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

void I3CBinding::initializeBinding()
{
    int status = 0;
    initializeMctp();
    hw->init();
    mctp_binding* binding = hw->binding();
    if (binding == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP I3C binding init");
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

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    // TODO. Set call back for bridging packets.
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));
    mctp_binding_set_tx_enabled(binding, true);

    hw->pollRx();

    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        endpointDiscoveryFlow();
    }
    mctpInterface->set_property(
            "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));
}

std::optional<std::vector<uint8_t>>
    I3CBinding::getBindingPrivateData(uint8_t /*dstEid*/)
{
    struct mctp_asti3c_pkt_private pktPrv;
    pktPrv.fd = mctpI3cFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData = std::vector<uint8_t>(
        pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

    return prvData;    
}

void I3CBinding::changeDiscoveredFlag(i3c_binding::DiscoveryFlags flag)
{
    discoveredFlag = flag;
    i3cInterface->set_property(
        "DiscoveredFlag", i3c_binding::convertDiscoveryFlagsToString(flag));

    if (i3c_binding::DiscoveryFlags::Discovered == flag)
    {
        getRoutingTableTimer.expires_from_now(boost::posix_time::seconds{0});
    }
}
