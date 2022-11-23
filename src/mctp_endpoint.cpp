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

#include "mctp_endpoint.hpp"

#include "mctp_cmd_encoder.hpp"
#include "utils/utils.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

using RoutingTableEntry = mctpd::RoutingTable::Entry;

constexpr int maxNumRoutingEntries = 256;

MCTPEndpoint::MCTPEndpoint(std::shared_ptr<sdbusplus::asio::connection> conn,
                           boost::asio::io_context& ioc,
                           std::shared_ptr<object_server>& objServer) :
    MCTPDevice(ioc, objServer),
    connection(conn)
{
}

bool MCTPEndpoint::isReceivedPrivateDataCorrect(const void* /*bindingPrivate*/)
{
    return true;
}

void MCTPEndpoint::handleCtrlReq(uint8_t destEid, void* bindingPrivate,
                                 const void* req, size_t len, uint8_t msgTag)
{
    if (req == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request is not initialized.");
        return;
    }
    if (!isReceivedPrivateDataCorrect(bindingPrivate))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Binding Private Data is not correct.");
        return;
    }

    std::vector<uint8_t> response = {};
    bool sendResponse = false;
    auto reqPtr = reinterpret_cast<const uint8_t*>(req);
    std::vector<uint8_t> request(reqPtr, reqPtr + len);
    mctp_ctrl_msg_hdr* reqHeader =
        reinterpret_cast<mctp_ctrl_msg_hdr*>(request.data());

    if (!reqHeader)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control Request Header is null");
        return;
    }

    switch (reqHeader->command_code)
    {
        case MCTP_CTRL_CMD_PREPARE_ENDPOINT_DISCOVERY: {
            sendResponse = handlePrepareForEndpointDiscovery(
                destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_ENDPOINT_DISCOVERY: {
            sendResponse = handleEndpointDiscovery(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ENDPOINT_ID: {
            sendResponse =
                handleGetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_SET_ENDPOINT_ID: {
            sendResponse =
                handleSetEndpointId(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VERSION_SUPPORT: {
            sendResponse = handleGetVersionSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT: {
            sendResponse = handleGetMsgTypeSupport(destEid, bindingPrivate,
                                                   request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_VENDOR_MESSAGE_SUPPORT: {
            sendResponse =
                handleGetVdmSupport(destEid, bindingPrivate, request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ROUTING_TABLE_ENTRIES: {
            sendResponse = handleGetRoutingTable(request, response);
            break;
        }
        case MCTP_CTRL_CMD_ALLOCATE_ENDPOINT_IDS: {
            sendResponse = handleAllocateEID(request, response);
            break;
        }
        case MCTP_CTRL_CMD_GET_ENDPOINT_UUID: {
            sendResponse = handleGetUUID(request, response);
            break;
        }
        case MCTP_CTRL_CMD_DISCOVERY_NOTIFY: {
            sendResponse = handleDiscoveryNotify(destEid, bindingPrivate,
                                                 request, response);
            break;
        }
        case MCTP_CTRL_CMD_ROUTING_INFO_UPDATE: {
            sendResponse = handleRoutingInfoUpdate(destEid, bindingPrivate,
                                                   request, response);
            break;
        }

        default: {
            std::stringstream commandCodeHex;
            commandCodeHex << std::hex
                           << static_cast<int>(reqHeader->command_code);
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                ("Device EID = " + std::to_string(destEid) +
                 " requested control command code = 0x" + commandCodeHex.str() +
                 " is not supported")
                    .c_str());

            auto resp =
                castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
            sendResponse = encode_cc_only_response(
                MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
        }
    }

    if (sendResponse)
    {
        auto respHeader = reinterpret_cast<mctp_ctrl_msg_hdr*>(response.data());
        *respHeader = *reqHeader;
        respHeader->rq_dgram_inst &=
            static_cast<uint8_t>(~MCTP_CTRL_HDR_FLAG_REQUEST);
        mctp_message_tx(mctp, destEid, response.data(), response.size(), false,
                        msgTag, bindingPrivate);
    }
    return;
}

bool MCTPEndpoint::handleRoutingInfoUpdate(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Routing infomation update command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

bool MCTPEndpoint::handleDiscoveryNotify(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    bool busownerMode =
        bindingModeType == mctp_server::BindingModeTypes::BusOwner;

    response.resize(sizeof(mctp_ctrl_msg_hdr));

    if (busownerMode)
    {
        response.push_back(static_cast<uint8_t>(MCTP_CTRL_CC_SUCCESS));
    }
    else
    {
        response.push_back(
            static_cast<uint8_t>(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD));
    }

    return true;
}

void MCTPEndpoint::setDownStreamEIDPools(uint8_t eidPoolSize, uint8_t firstEID)
{
    boost::asio::spawn(io, [this, eidPoolSize,
                            firstEID](boost::asio::yield_context yield) {
        uint8_t remainingPoolSize = eidPoolSize;
        uint8_t startEID = firstEID;

        for (auto& [busName, poolSize] : downstreamEIDPools)
        {
            boost::system::error_code ec;

            // Check if startEID + poolsize overruns 255 EID
            if (startEID > (0xFF - poolSize))
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("EID pool crossing EID range on bus:" + busName).c_str());
                continue;
            }

            if (remainingPoolSize < poolSize)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("Running out of eid pool for bus" + busName).c_str());
                // Check if remaining pool can be distributed
                continue;
            }
            auto rc = connection->yield_method_call<bool>(
                yield, ec, busName, "/xyz/openbmc_project/mctp",
                mctp_server::interface, "SetEIDPool", startEID, poolSize);

            for (uint8_t i = 0; i <= poolSize; i++)
            {
                // Endpoint details will be invalid since these eids are not yet
                // assigned.
                uint8_t eid = startEID + i;
                mctpd::RoutingTable::Entry entry(eid, busName,
                                                 mctpd::EndPointType::EndPoint);
                entry.isUpstream = true;
                this->routingTable.updateEntry(eid, entry);
            }

            if (ec || !rc)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    ("Error setting EID pool for: " + busName).c_str());
                continue;
            }

            for (uint8_t i = 0; i < poolSize; i++)
            {
                // Endpoint details will be invalid since these eids are not yet
                // assigned.
                uint8_t eid = startEID + i;
                mctpd::RoutingTable::Entry entry(eid, busName,
                                                 mctpd::EndPointType::EndPoint);
                entry.isUpstream = true;
                this->routingTable.updateEntry(eid, entry);
            }

            startEID += poolSize;
            remainingPoolSize -= poolSize;
        }
    });
}

bool MCTPEndpoint::handleAllocateEID(std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response)
{
    auto req =
        reinterpret_cast<mctp_ctrl_cmd_allocate_eids_req*>(request.data());
    uint8_t icMsgType;
    uint8_t rqDgramInstanceID;
    uint8_t commandCode;
    mctp_ctrl_cmd_allocate_eids_req_op op;
    uint8_t eidPoolSize;
    uint8_t firstEID;

    response.resize(sizeof(mctp_ctrl_cmd_allocate_eids_resp));
    auto resp =
        reinterpret_cast<mctp_ctrl_cmd_allocate_eids_resp*>(response.data());

    if (!mctp_decode_ctrl_cmd_allocate_endpoint_id_req(
            req, &icMsgType, &rqDgramInstanceID, &commandCode, &op,
            &eidPoolSize, &firstEID))
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        return true;
    }

    if (requiredEIDPoolSizeFromBO.has_value())
    {
        switch (op)
        {
            case allocate_eids:
            case force_allocation: {
                if (eidPoolSize > requiredEIDPoolSizeFromBO.value())
                {
                    resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
                    resp->operation = allocation_rejected;
                }
                else
                {
                    if (!mctp_encode_ctrl_cmd_allocate_endpoint_id_resp(
                            resp, &req->ctrl_msg_hdr, allocation_accepted,
                            eidPoolSize, firstEID))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "Encode allocate EID failed");
                        resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
                        return true;
                    }
                    setDownStreamEIDPools(eidPoolSize, firstEID);
                    allocatedPoolSize = eidPoolSize;
                    allocatedPoolFirstEID = firstEID;
                }
                break;
            }
            case get_allocation_info: {
                if (!mctp_encode_ctrl_cmd_allocate_endpoint_id_resp(
                        resp, &req->ctrl_msg_hdr, allocation_accepted,
                        allocatedPoolSize, allocatedPoolFirstEID))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Encode allocate EID failed");
                    resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
                    return true;
                }
                break;
            }

            default:
                resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Allocate EID is not supported for this simple endpoint");
        resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
    }
    return true;
}

bool MCTPEndpoint::handleGetUUID(std::vector<uint8_t>& request,
                                 std::vector<uint8_t>& response)
{
    response.resize(sizeof(mctp_ctrl_resp_get_uuid));
    auto resp = reinterpret_cast<mctp_ctrl_resp_get_uuid*>(response.data());
    auto req = reinterpret_cast<mctp_ctrl_cmd_get_uuid*>(request.data());

    if (uuid.size() < sizeof(guid_t))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid size of UUID");
        return false;
    }

    if (!mctp_encode_ctrl_cmd_get_uuid_resp(
            resp, &req->ctrl_msg_hdr,
            (reinterpret_cast<const guid_t*>(uuid.data()))))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Encode get uuid failed");
        return false;
    }

    return true;
}

bool MCTPEndpoint::handlePrepareForEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Prepare For Endpoint Discovery command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

bool MCTPEndpoint::handleEndpointDiscovery(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Endpoint Discovery command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

bool MCTPEndpoint::handleGetEndpointId(
    mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{

    auto resp = castVectorToStruct<mctp_ctrl_resp_get_eid>(response);

    bool busownerMode =
        bindingModeType == mctp_server::BindingModeTypes::BusOwner ? true
                                                                   : false;
    mctp_ctrl_cmd_get_endpoint_id(mctp, destEid, busownerMode, resp);

    if (requiredEIDPoolSizeFromBO.has_value() || busownerMode)
    {
        resp->eid_type =
            (ENDPOINT_TYPE_BUS_OWNER_BRIDGE << ENDPOINT_TYPE_SHIFT);
    }
    return true;
}

bool MCTPEndpoint::handleSetEndpointId(mctp_eid_t destEid,
                                       [[maybe_unused]] void* bindingPrivate,
                                       std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response)
{
    auto resp = castVectorToStruct<mctp_ctrl_resp_set_eid>(response);
    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
        return true;
    }
    if (!is_eid_valid(destEid))
    {
        resp->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        return true;
    }
    auto req = reinterpret_cast<mctp_ctrl_cmd_set_eid*>(request.data());

    mctp_ctrl_cmd_set_endpoint_id(mctp, destEid, req, resp);
    if (resp->completion_code == MCTP_CTRL_CC_SUCCESS)
    {
        if (supportsBridge)
        {
            // Remove the OwnEid from the Routing table
            routingTable.removeEntry(ownEid);
        }

        busOwnerEid = destEid;
        ownEid = resp->eid_set;
    }

    if (requiredEIDPoolSizeFromBO.has_value())
    {
        resp->status |= 1;
        resp->eid_pool_size = requiredEIDPoolSizeFromBO.value();
    }
    if (supportsBridge)
    {
        // add NewEid value to the Routing table
        addOwnEIDToRoutingTable();
    }

    return true;
}

bool MCTPEndpoint::handleGetVersionSupport(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    std::vector<uint8_t>& request, std::vector<uint8_t>& response)
{
    auto req =
        reinterpret_cast<mctp_ctrl_cmd_get_mctp_ver_support*>(request.data());
    auto resp =
        castVectorToStruct<mctp_ctrl_resp_get_mctp_ver_support>(response);

    auto itVer =
        versionNumbersForUpperLayerResponder.find(req->msg_type_number);
    if (itVer == versionNumbersForUpperLayerResponder.end() ||
        itVer->second.empty())
    {
        resp->completion_code =
            MCTP_CTRL_CC_GET_MCTP_VER_SUPPORT_UNSUPPORTED_TYPE;
        resp->number_of_entries = 0; // No supported versions
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("No supported version available for " +
             std::to_string(req->msg_type_number))
                .c_str());
    }
    else
    {
        resp->completion_code = MCTP_CTRL_CC_SUCCESS;
        resp->number_of_entries = static_cast<uint8_t>(itVer->second.size());
        std::copy(reinterpret_cast<uint8_t*>(itVer->second.data()),
                  reinterpret_cast<uint8_t*>(itVer->second.data()) +
                      itVer->second.size() * sizeof(version_entry),
                  std::back_inserter(response));
    }
    return true;
}

std::vector<uint8_t> MCTPEndpoint::getBindingMsgTypes()
{
    std::vector<uint8_t> bindingMsgTypes;
    for (const auto& [type, ver] : versionNumbersForUpperLayerResponder)
    {
        if (type == MCTP_GET_VERSION_SUPPORT_BASE_INFO)
        {
            continue;
        }
        bindingMsgTypes.emplace_back(type);
    }
    return bindingMsgTypes;
}

bool MCTPEndpoint::handleGetMsgTypeSupport(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    std::vector<uint8_t>& response)
{
    std::vector<uint8_t> supportedMsgTypes = getBindingMsgTypes();
    auto resp =
        castVectorToStruct<mctp_ctrl_resp_get_msg_type_support>(response);
    resp->completion_code = MCTP_CTRL_CC_SUCCESS;
    resp->msg_type_count = static_cast<uint8_t>(supportedMsgTypes.size());
    std::copy(supportedMsgTypes.begin(), supportedMsgTypes.end(),
              std::back_inserter(response));
    return true;
}

bool MCTPEndpoint::handleGetVdmSupport(
    [[maybe_unused]] mctp_eid_t destEid, [[maybe_unused]] void* bindingPrivate,
    [[maybe_unused]] std::vector<uint8_t>& request,
    [[maybe_unused]] std::vector<uint8_t>& response)
{
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Get Vendor Defined Message command not supported");
    auto resp = castVectorToStruct<mctp_ctrl_resp_completion_code>(response);
    return encode_cc_only_response(MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD, resp);
}

bool MCTPEndpoint::handleGetRoutingTable(const std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response)
{
    static constexpr size_t errRespSize = 3;
    if (bindingModeType == mctp_server::BindingModeTypes::Endpoint &&
        !supportsBridge)
    {
        // Command is not supported for endpoints. No response will be sent
        return false;
    }
    auto getRoutingTableRequest =
        reinterpret_cast<const mctp_ctrl_cmd_get_routing_table*>(
            request.data());
    auto dest =
        reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(response.data());

    bool status = false;
    const mctpd::RoutingTable::EntryMap& entries =
        this->routingTable.getAllEntries();
    std::vector<RoutingTableEntry::MCTPLibData> entriesLibFormat;

    std::vector<RoutingTableEntry::MCTPLibData> requiredEntriesLibFormat;

    // TODO. Combine EIDs in a range.
    for (const auto& [eid, data] : entries)
    {
        entriesLibFormat.emplace_back(data.routeEntry);
    }
    size_t startIndex =
        maxNumRoutingEntries * getRoutingTableRequest->entry_handle;
    size_t endIndex = startIndex + maxNumRoutingEntries - 1;
    uint8_t next_entry_handle = getRoutingTableRequest->entry_handle + 1;

    if (entriesLibFormat.size() < startIndex + 1)
    {
        response.resize(errRespSize);
        dest->completion_code = MCTP_CTRL_CC_ERROR_INVALID_DATA;
        dest->number_of_entries = 0;
        // Return true so that a response will be sent with error code
        return true;
    }
    if (entriesLibFormat.size() < endIndex + 1)
    {
        endIndex = entriesLibFormat.size();
        next_entry_handle = 0xFF;
    }

    for (size_t i = startIndex; i < endIndex; i++)
    {
        requiredEntriesLibFormat.emplace_back(entriesLibFormat[i]);
    }

    size_t estSize = sizeof(mctp_ctrl_resp_get_routing_table) +
                     requiredEntriesLibFormat.size() *
                         sizeof(get_routing_table_entry_with_address);

    response.resize(estSize);
    size_t formattedRespSize = 0;
    dest = reinterpret_cast<mctp_ctrl_resp_get_routing_table*>(response.data());

    if (!mctp_encode_ctrl_cmd_get_routing_table_resp(
            dest, requiredEntriesLibFormat.data(),
            static_cast<uint8_t>(requiredEntriesLibFormat.size()),
            &formattedRespSize, next_entry_handle))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error formatting get routing table");
        formattedRespSize = 0;
    }
    response.resize(formattedRespSize);
    status = true;
    return status;
}

bool MCTPEndpoint::discoveryNotifyCtrlCmd(
    boost::asio::yield_context& yield,
    const std::vector<uint8_t>& bindingPrivate, const mctp_eid_t destEid)
{
    std::vector<uint8_t> req = {};
    std::vector<uint8_t> resp = {};

    if (!getFormattedReq<MCTP_CTRL_CMD_DISCOVERY_NOTIFY>(req))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Request formatting failed");
        return false;
    }

    if (PacketState::receivedResponse !=
        sendAndRcvMctpCtrl(yield, req, destEid, bindingPrivate, resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify: Unable to get response");
        return false;
    }

    if (!checkRespSizeAndCompletionCode<mctp_ctrl_resp_discovery_notify>(resp))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Discovery Notify failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Discovery Notify success");
    return true;
}
