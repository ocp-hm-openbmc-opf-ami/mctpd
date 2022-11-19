#include "I3CBinding.hpp"

#include "utils/utils.hpp"

#include <phosphor-logging/log.hpp>

I3CBinding::~I3CBinding()
{
    objectServer->remove_interface(i3cInterface);
}

I3CBinding::I3CBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                       std::shared_ptr<object_server>& objServer,
                       const std::string& objPath, const I3CConfiguration& conf,
                       boost::asio::io_context& ioc,
                       std::unique_ptr<hw::I3CDriver>&& hwParam) :
    MctpBinding(conn, objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverI3c),
    hw{std::move(hwParam)}, getRoutingInterval(conf.getRoutingInterval),
    getRoutingTableTimer(ioc, getRoutingInterval), i3cConf(conf),
    forwaredEIDPoolToEP(conf.forwaredEIDPoolToEP),
    blockDiscoveryNotify(conf.blockDiscoveryNotify)
{
    i3cInterface =
        objServer->add_interface(objPath, I3CBindingServer::interface);

    try
    {
        mctpI3CFd = hw->getDriverFd();

        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
        {
            discoveredFlag = I3CBindingServer::DiscoveryFlags::NotApplicable;
            if (conf.requiredEIDPoolSize > 0)
            {
                // EID pool will be assigned through a Topmost busowner
                // dynamically
                requiredEIDPoolSize = conf.requiredEIDPoolSize;
            }
            else
            {
                // Static EID pool
                eidPool.initializeEidPool(conf.eidPool);
            }
        }
        else
        {
            discoveredFlag = I3CBindingServer::DiscoveryFlags::Undiscovered;
            if (conf.requiredEIDPoolSizeFromBO > 0)
            {
                requiredEIDPoolSizeFromBO = conf.requiredEIDPoolSizeFromBO;
                downstreamEIDPools = conf.downstreamEIDPoolDistribution;
            }
        }
        ownI3cDAA = hw->getOwnAddress();
        registerProperty(i3cInterface, "Address", ownI3cDAA);

        registerProperty(
            i3cInterface, "DiscoveredFlag",
            I3CBindingServer::convertDiscoveryFlagsToString(discoveredFlag));
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

void I3CBinding::triggerDeviceDiscovery()
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Triggering device discovery");
    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        discoveredFlag = I3CBindingServer::DiscoveryFlags::Undiscovered;
        for (auto& routingEntry : routingTable)
        {
            unregisterEndpoint(std::get<0>(routingEntry));
        }
        routingTable = {};
        mctpI3CFd = hw->getDriverFd();
        hw->pollRx();
        endpointDiscoveryFlow();
    }
}

void I3CBinding::endpointDiscoveryFlow()
{
    struct mctp_asti3c_pkt_private pktPrv;
    pktPrv.fd = mctpI3CFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));
    changeDiscoveredFlag(I3CBindingServer::DiscoveryFlags::Undiscovered);

    if (this->blockDiscoveryNotify)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Discovery notify sending disabled using config value");
        return;
    }

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        bool discoverNoftifyDone = false;
        constexpr const uint8_t maxRetryCount = 3;
        uint8_t retryCount = 0;
        while (!discoverNoftifyDone &&
               (discoveredFlag ==
                I3CBindingServer::DiscoveryFlags::Undiscovered) &&
               (retryCount < maxRetryCount))
        {
            if (!discoveryNotifyCtrlCmd(yield, prvData, MCTP_EID_NULL))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Discovery Notify failed");
                retryCount++;
            }
            else
            {
                discoverNoftifyDone = true;
            }
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

std::optional<uint8_t> I3CBinding::getRoutingEntryPhysAddr(
    const std::vector<uint8_t>& getRoutingTableEntryResp, size_t entryOffset)
{
    if (entryOffset >= getRoutingTableEntryResp.size())
    {
        return std::nullopt;
    }
    return getRoutingTableEntryResp[entryOffset];
}

bool I3CBinding::isEntryInRoutingTable(
    get_routing_table_entry* routingEntry,
    const std::vector<routingTableEntry_t>& rt)
{
    return std::find_if(
               rt.begin(), rt.end(), [&routingEntry](const auto& entry) {
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
                                            uint8_t responseCount)
{
    if (entryHandle == 0xff || responseCount == 0xff)
    {
        return true;
    }
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
        {
            return false;
        }
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
        responseCount++;
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
            if ((routingTableEntry->phys_transport_binding_id !=
                 MCTP_BINDING_I3C) ||
                (routingTableEntry->phys_media_type_id !=
                 static_cast<uint8_t>(
                     mctpd::PhysicalMediumIdentifier::i3c12_5Mhz)))

            {
                entryOffset += routingTableEntry->phys_address_size;
                continue;
            }
            std::optional<uint8_t> entryPhysAddr =
                getRoutingEntryPhysAddr(getRoutingTableEntryResp, entryOffset);

            if (!entryPhysAddr)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Parsing physical address from entry failed");
                continue;
            }

            entryOffset += routingTableEntry->phys_address_size;

            if (eid == busOwnerEid &&
                GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                    MCTP_ROUTING_ENTRY_BRIDGE_AND_ENDPOINTS)
            {
                rt.push_back(std::make_tuple(
                    routingTableEntry->starting_eid, *entryPhysAddr,
                    SET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type,
                                           MCTP_ROUTING_ENTRY_BRIDGE)));
            }
            else if (eid == busOwnerEid &&
                     !(GET_ROUTING_ENTRY_TYPE(routingTableEntry->entry_type) ==
                       MCTP_ROUTING_ENTRY_ENDPOINTS))
            {
                rt.push_back(std::make_tuple(routingTableEntry->starting_eid,
                                             *entryPhysAddr,
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
        {
            continue;
        }

        mctp_asti3c_pkt_private pktPrv;
        pktPrv.fd = mctpI3CFd;
        uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
        std::vector<uint8_t> prvData =
            std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

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

    if (!this->blockDiscoveryNotify &&
        discoveredFlag != I3CBindingServer::DiscoveryFlags::Discovered)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Get Routing Table failed, undiscovered");
        return;
    }
    pktPrv.fd = mctpI3CFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

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
    uint8_t deviceAddress = 0;
    std::string mctpEpObj =
        "/xyz/openbmc_project/mctp/device/" + std::to_string(eid);
    std::shared_ptr<dbus_interface> i3cIntf;
    // TODO: Read symlinks and find the DAA getDAAfromFd()
    i3cIntf = objectServer->add_interface(
        mctpEpObj, "xyz.openbmc_project.Inventory.Decorator.I3CDevice");
    i3cIntf->register_property("Bus", i3cConf.bus);
    deviceAddress = hw->getDeviceAddress();
    i3cIntf->register_property("Address", deviceAddress);
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
            if (this->blockDiscoveryNotify &&
                !MctpBinding::routingTable.contains(remoteEid))
            {
                // EID already existing in routing table indicates that it came
                // as part of allocate eid command
                if (remoteEid == MCTP_EID_NULL ||
                    remoteEid == MCTP_EID_BROADCAST)
                {
                    continue;
                }
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    ("Registering EID without asking anything. " +
                     std::to_string(remoteEid))
                        .c_str());
                EndpointProperties epProperties;
                epProperties.endpointEid = remoteEid;
                epProperties.mode = sdbusplus::xyz::openbmc_project::MCTP::
                    server::Base::BindingModeTypes::Endpoint;

                const auto phyMediumId = static_cast<uint8_t>(
                    mctpd::convertToPhysicalMediumIdentifier(bindingMediumID));
                mctpd::RoutingTable::Entry entry(
                    remoteEid, getDbusName(), mctpd::EndPointType::EndPoint,
                    phyMediumId, getTransportId(),
                    std::vector<uint8_t>({std::get<1>(routingEntry)}));
                MctpBinding::routingTable.updateEntry(remoteEid, entry);
                populateEndpointProperties(epProperties);
                continue;
            }
            std::vector<uint8_t> prvDataCopy = prvData;
            registerEndpoint(yield, prvDataCopy, remoteEid,
                             getBindingMode(routingEntry));

            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("I3C device at bus " + std::to_string(bus) + " and address " +
                 std::to_string(ownI3cDAA) + " registered at EID " +
                 std::to_string(remoteEid))
                    .c_str());
        }
    }
}

bool I3CBinding::handleDiscoveryNotify(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_msg_hdr));

    // If we are I3C secondary device, our DAA might be updated when we receive
    // Discovery notify Thus update the our own DAA on D-Bus
    ownI3cDAA = hw->getOwnAddress();
    i3cInterface->set_property("Address", ownI3cDAA);
    bool busownerMode =
        bindingModeType == mctp_server::BindingModeTypes::BusOwner ? true
                                                                   : false;

    if (busownerMode)
    {
        response.push_back(static_cast<uint8_t>(MCTP_CTRL_CC_SUCCESS));

        // Create a co-routine and register the endpoint
        boost::asio::spawn(
            io, [this, destEid](boost::asio::yield_context yield) {
                mctp_asti3c_pkt_private pktPrv;
                pktPrv.fd = mctpI3CFd;
                uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
                std::vector<uint8_t> prvData =
                    std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));
                registerEndpoint(yield, prvData, destEid);
            });
    }
    else
    {
        response.push_back(
            static_cast<uint8_t>(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD));
    }

    return true;
}

bool I3CBinding::handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response)
{
    return MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                            response);
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
        changeDiscoveredFlag(I3CBindingServer::DiscoveryFlags::Discovered);
        mctpInterface->set_property("Eid", ownEid);
    }
    return true;
}

bool I3CBinding::handleGetVersionSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response)
{
    return MctpBinding::handleGetVersionSupport(destEid, bindingPrivate,
                                                request, response);
}

bool I3CBinding::handleGetMsgTypeSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response)
{
    return MctpBinding::handleGetMsgTypeSupport(destEid, bindingPrivate,
                                                request, response);
}

bool I3CBinding::handleGetVdmSupport(mctp_eid_t destEid,
                                     void* /*bindingPrivate*/,
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
    if (is_eid_valid(i3cConf.defaultEid))
    {
        mctp_dynamic_eid_set(binding, i3cConf.defaultEid);
    }

    if (status < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Bus registration of binding failed");
        throw std::system_error(
            std::make_error_code(static_cast<std::errc>(-status)));
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    mctp_set_rx_raw(mctp, &MctpBinding::onRawMessage);
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));
    mctp_binding_set_tx_enabled(binding, true);

    setupHostResetMatch(connection, this);

    hw->pollRx();

    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        endpointDiscoveryFlow();
    }

    else
    {
        // Check if we have a static pool
        if (!requiredEIDPoolSize.has_value())
        {
            mctp_dynamic_eid_set(binding, ownEid);
        }
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
    pktPrv.fd = mctpI3CFd;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData =
        std::vector<uint8_t>(pktPrvPtr, pktPrvPtr + sizeof(pktPrv));

    return prvData;
}

void I3CBinding::changeDiscoveredFlag(I3CBindingServer::DiscoveryFlags flag)
{
    discoveredFlag = flag;
    i3cInterface->set_property(
        "DiscoveredFlag",
        I3CBindingServer::convertDiscoveryFlagsToString(flag));

    if (I3CBindingServer::DiscoveryFlags::Discovered == flag)
    {
        constexpr const uint8_t waitForEidPoolDelaySeconds = 5;
        getRoutingTableTimer.expires_from_now(
            boost::posix_time::seconds{waitForEidPoolDelaySeconds});
    }
}

uint8_t I3CBinding::getTransportId()
{
    return MCTP_BINDING_I3C;
}

std::vector<uint8_t>
    I3CBinding::getPhysicalAddress(const std::vector<uint8_t>& /*privateData*/)
{
    // Update proper physical address
    return std::vector<uint8_t>{hw->getDeviceAddress()};
}

std::vector<uint8_t> I3CBinding::getOwnPhysicalAddress()
{
    // Update proper physical address
    return std::vector<uint8_t>{hw->getOwnAddress()};
}

bool I3CBinding::setEIDPool(const uint8_t startEID, const uint8_t poolSize)
{
    if (!MctpBinding::setEIDPool(startEID, poolSize))
    {
        return false;
    }
    if (this->forwaredEIDPoolToEP)
    {
        boost::asio::spawn(
            this->connection->get_io_context(),
            [this, startEID, poolSize](boost::asio::yield_context yield) {
                if (!this->forwardEIDPool(yield, startEID, poolSize))
                {
                    return;
                }
                // Add forwarded eid entries in routing table with physical
                // details of i3c target device
                for (uint8_t i = 0; i < poolSize; i++)
                {
                    // Endpoint details will be invalid since these eids are not
                    // yet assigned.
                    uint8_t eid = startEID + i;
                    mctpd::RoutingTable::Entry entry(
                        eid, getDbusName(), mctpd::EndPointType::EndPoint);
                    entry.isUpstream = false;
                    this->MctpBinding::routingTable.updateEntry(eid, entry);
                }
            });
    }
    return true;
}

bool I3CBinding::forwardEIDPool(boost::asio::yield_context& yield,
                                const uint8_t startEID, const uint8_t poolSize)
{
    std::vector<uint8_t> resp;
    if (!this->allocateEIDPoolCtrlCmd(
            yield, MCTP_EID_NULL,
            mctp_ctrl_cmd_allocate_eids_req_op::allocate_eids, startEID,
            poolSize, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error while sending Allocate EID during forward eid pool");
        return false;
    }

    mctp_ctrl_cmd_allocate_eids_resp respData;
    mctp_ctrl_cmd_allocate_eids_resp_op op;

    auto response =
        reinterpret_cast<mctp_ctrl_cmd_allocate_eids_resp*>(resp.data());
    mctp_msg* mctp_resp = reinterpret_cast<mctp_msg*>(response);

    if (mctp_decode_allocate_endpoint_id_resp(
            mctp_resp, sizeof(struct mctp_ctrl_cmd_allocate_eids_resp),
            &respData.ctrl_hdr, &respData.completion_code, &op,
            &respData.eid_pool_size, &respData.first_eid))
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Allocate EID decode error");
        return false;
    }
    if (respData.completion_code != MCTP_CTRL_CC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Allocate EID was not succesful");
        return false;
    }
    if (respData.operation !=
        mctp_ctrl_cmd_allocate_eids_resp_op::allocation_accepted)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Allocate EID rejected by the endpoint");
        return false;
    }
    return true;
}