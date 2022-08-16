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

#include "smbus_endpoint.hpp"

#include "utils/utils.hpp"

#include <libmctp-smbus.h>

#include <phosphor-logging/log.hpp>

SMBusEndpoint::SMBusEndpoint(std::shared_ptr<sdbusplus::asio::connection> conn,
                             std::shared_ptr<object_server>& objServer,
                             const std::string& objPath,
                             const SMBusConfiguration& conf,
                             boost::asio::io_context& ioc) :
    SMBusDevice(conn, objServer, objPath, conf, ioc)
{
    smbusRoutingTableTimer = std::make_unique<boost::asio::steady_timer>(ioc);
}

bool SMBusEndpoint::handlePrepareForEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Prepare For Endpoint Discovery command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

bool SMBusEndpoint::handleEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Endpoint Discovery command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

// TODO: This method is a placeholder and has not been tested
bool SMBusEndpoint::handleGetEndpointId(mctp_eid_t destEid,
                                        void* bindingPrivate,
                                        std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleGetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    auto const ptr = reinterpret_cast<uint8_t*>(bindingPrivate);

    if (auto bindingPvtVect = getBindingPrivateData(destEid))
    {
        std::copy(bindingPvtVect->begin(), bindingPvtVect->end(), ptr);
        return true;
    }
    return false;
}

bool SMBusEndpoint::handleSetEndpointId(mctp_eid_t destEid,
                                        void* bindingPrivate,
                                        std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response)
{
    if (!MctpBinding::handleSetEndpointId(destEid, bindingPrivate, request,
                                          response))
    {
        return false;
    }

    auto resp = castVectorToStruct<mctp_ctrl_resp_set_eid>(response);

    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        updateDiscoveredFlag(DiscoveryFlags::kDiscovered);
        mctpInterface->set_property("Eid", ownEid);

        mctp_smbus_pkt_private* smbusPrivate =
            reinterpret_cast<mctp_smbus_pkt_private*>(bindingPrivate);
        busOwnerSlaveAddr = smbusPrivate->slave_addr;
        busOwnerFd = smbusPrivate->fd;

        if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
        {
            updateRoutingTable();
        }
    }

    return true;
}

bool SMBusEndpoint::handleGetVersionSupport(mctp_eid_t destEid,
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

bool SMBusEndpoint::handleGetMsgTypeSupport(mctp_eid_t destEid,
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

bool SMBusEndpoint::handleGetVdmSupport(mctp_eid_t destEid,
                                        [[maybe_unused]] void* bindingPrivate,
                                        std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response)
{
    if (request.size() < sizeof(struct mctp_ctrl_cmd_get_vdm_support))
    {
        return false;
    }

    struct mctp_ctrl_cmd_get_vdm_support* req =
        reinterpret_cast<struct mctp_ctrl_cmd_get_vdm_support*>(request.data());

    /* Generic library API. Specialized later on. */
    struct mctp_ctrl_resp_get_vdm_support* libResp =
        castVectorToStruct<mctp_ctrl_resp_get_vdm_support>(response);

    if (mctp_ctrl_cmd_get_vdm_support(mctp, destEid, libResp) < 0)
    {
        return false;
    }

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

bool SMBusEndpoint::handleResolveEndpointId(mctp_eid_t destEid,
                                            void* bindingPrivate,
                                            std::vector<uint8_t>& request,
                                            std::vector<uint8_t>& response)
{
    if (!MCTPEndpoint::handleResolveEndpointId(destEid, bindingPrivate, request,
                                               response))
        return false;

    auto resp =
        castVectorToStruct<mctp_ctrl_cmd_resolve_eid_resp>(response);
    if (resp->bridge_eid == destEid)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "EId's Are same! Not a Bridge, Target Device On Same Bus");
    }
    return true;
}

std::string SMBusEndpoint::convertToString(DiscoveryFlags flag)
{
    std::string discoveredStr;
    switch (flag)
    {
        case DiscoveryFlags::kUnDiscovered: {
            discoveredStr = "Undiscovered";
            break;
        }
        case DiscoveryFlags::kDiscovered: {
            discoveredStr = "Discovered";
            break;
        }
        case DiscoveryFlags::kNotApplicable:
        default: {
            discoveredStr = "NotApplicable";
            break;
        }
    }

    return discoveredStr;
}

void SMBusEndpoint::updateDiscoveredFlag(DiscoveryFlags flag)
{
    discoveredFlag = flag;
    smbusInterface->set_property("DiscoveredFlag", convertToString(flag));
}

void SMBusEndpoint::updateRoutingTable()
{
    if (discoveredFlag != DiscoveryFlags::kDiscovered)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Get Routing Table failed, undiscovered");
        return;
    }

    struct mctp_smbus_pkt_private pktPrv = {};
    pktPrv.fd = busOwnerFd;
    pktPrv.mux_hold_timeout = 0;
    pktPrv.mux_flags = 0;
    pktPrv.slave_addr = busOwnerSlaveAddr;
    uint8_t* pktPrvPtr = reinterpret_cast<uint8_t*>(&pktPrv);
    std::vector<uint8_t> prvData = std::vector<uint8_t>(
        pktPrvPtr, pktPrvPtr + sizeof(mctp_smbus_pkt_private));

    boost::asio::spawn(io, [prvData, this](boost::asio::yield_context yield) {
        std::vector<uint8_t> getRoutingTableEntryResp = {};
        std::vector<DeviceTableEntry_t> smbusDeviceTableTmp;
        uint8_t entryHandle = 0x00;
        uint8_t entryHdlCounter = 0x00;
        while ((entryHandle != 0xff) && (entryHdlCounter < 0xff))
        {
            if (!getRoutingTableCtrlCmd(yield, prvData, busOwnerEid,
                                        entryHandle, getRoutingTableEntryResp))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Get Routing Table failed");
                return;
            }

            auto routingTableHdr =
                reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(
                    getRoutingTableEntryResp.data());
            size_t phyAddrOffset = sizeof(mctp_ctrl_resp_get_routing_table);

            for (uint8_t entryIndex = 0;
                 entryIndex < routingTableHdr->number_of_entries; entryIndex++)
            {
                auto routingTableEntry =
                    reinterpret_cast<get_routing_table_entry*>(
                        getRoutingTableEntryResp.data() + phyAddrOffset);

                phyAddrOffset += sizeof(get_routing_table_entry);

                if ((routingTableEntry->phys_transport_binding_id ==
                     MCTP_BINDING_SMBUS) &&
                    (routingTableEntry->phys_address_size == 1))
                {
                    struct mctp_smbus_pkt_private smbusBindingPvt = {};
                    smbusBindingPvt.fd = busOwnerFd;
                    smbusBindingPvt.mux_hold_timeout = 0;
                    smbusBindingPvt.mux_flags = 0;
                    smbusBindingPvt.slave_addr = static_cast<uint8_t>(
                        (getRoutingTableEntryResp[phyAddrOffset] << 1));

                    for (uint8_t eidRange = 0;
                         eidRange < routingTableEntry->eid_range_size;
                         eidRange++)
                    {
                        smbusDeviceTableTmp.push_back(std::make_pair(
                            routingTableEntry->starting_eid + eidRange,
                            smbusBindingPvt));
                    }
                }
                phyAddrOffset += routingTableEntry->phys_address_size;
            }
            entryHandle = routingTableHdr->next_entry_handle;
        }

        if (isDeviceTableChanged(smbusDeviceTable, smbusDeviceTableTmp))
        {
            processRoutingTableChanges(smbusDeviceTableTmp, yield, prvData);
            smbusDeviceTable = smbusDeviceTableTmp;
        }
        entryHdlCounter++;
    });

    smbusRoutingTableTimer->expires_after(
        std::chrono::seconds(smbusRoutingInterval));
    smbusRoutingTableTimer->async_wait(
        std::bind(&SMBusEndpoint::updateRoutingTable, this));
}
