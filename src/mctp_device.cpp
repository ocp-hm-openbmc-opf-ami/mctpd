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

#include "mctp_device.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

constexpr unsigned int ctrlTxPollInterval = 5;
// Supported MCTP Version 1.3.1
struct MCTPVersionFields supportedMCTPVersion = {241, 243, 241, 0};

MCTPDevice::MCTPDevice(boost::asio::io_context& ioc,
                       std::shared_ptr<object_server>& objServer) :
    MCTPDBusInterfaces(objServer),
    io(ioc)
{
    initializeLogging();
    mctp = mctp_init();
    if (!mctp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to init mctp");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

MCTPDevice::~MCTPDevice()
{
    if (mctp)
    {
        mctp_destroy(mctp);
    }
}

void MCTPDevice::initializeLogging(void)
{
    // Default log level
    mctp_set_log_stdio(MCTP_LOG_INFO);

    if (auto envPtr = std::getenv("MCTP_TRACES"))
    {
        std::string value(envPtr);
        if (value == "1")
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "MCTP traces enabled, expect lower performance");
            mctp_set_log_stdio(MCTP_LOG_DEBUG);
            mctp_set_tracing_enabled(true);
        }
    }
}

std::optional<std::vector<uint8_t>>
    MCTPDevice::getBindingPrivateData(uint8_t /*dstEid*/)
{
    // No Binding data by default
    return std::vector<uint8_t>();
}

std::optional<std::string>
    MCTPDevice::getLocationCode(const std::vector<uint8_t>&)
{
    return std::nullopt;
}

void MCTPDevice::updateRoutingTableEntry(mctpd::RoutingTable::Entry,
                                         const std::vector<uint8_t>&)
{
    // Do nothing
}

PacketState MCTPDevice::sendAndRcvMctpCtrl(
    boost::asio::yield_context& yield, const std::vector<uint8_t>& req,
    const mctp_eid_t destEid, const std::vector<uint8_t>& bindingPrivate,
    std::vector<uint8_t>& resp)
{
    if (req.empty())
    {
        return PacketState::invalidPacket;
    }
    PacketState pktState = PacketState::pushedForTransmission;

    // If no reponse:
    // Retry the packet on every ctrlTxRetryDelay
    // Total no of tries = 1 + ctrlTxRetryCount
    for (int count = 0; count <= ctrlTxRetryCount; ++count)
    {
        boost::system::error_code ec;
        std::vector<uint8_t> reqTemp = req;
        std::vector<uint8_t> bindingPrivateTemp = bindingPrivate;

        auto message =
            transmissionQueue.transmit(mctp, destEid, std::move(reqTemp),
                                       std::move(bindingPrivateTemp), io);

        message->timer.expires_after(
            std::chrono::milliseconds(ctrlTxRetryDelay));
        message->timer.async_wait(yield[ec]);

        if (ec && ec != boost::asio::error::operation_aborted)
        {
            transmissionQueue.dispose(destEid, message);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "sendAndRcvMctpCtrl: Timer failed");
            continue;
        }
        pktState = PacketState::transmitted;
        if (!message->response)
        {
            transmissionQueue.dispose(destEid, message);
            pktState = PacketState::noResponse;
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "sendAndRcvMctpCtrl: No response. Device busy or doesn't "
                "support MCTP?");
            continue;
        }
        if (message->response->empty())
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "sendAndRcvMctpCtrl: Empty response");
        }
        resp = std::move(message->response).value();
        pktState = PacketState::receivedResponse;
        break;
    }

    return pktState;
}

mctp_server::BindingModeTypes MCTPDevice::getEndpointType(const uint8_t types)
{
    constexpr uint8_t endpointTypeMask = 0x30;
    constexpr int endpointTypeShift = 0x04;
    constexpr uint8_t simpleEndpoint = 0x00;
    constexpr uint8_t busOwnerBridge = 0x01;

    uint8_t endpointType = (types & endpointTypeMask) >> endpointTypeShift;

    if (endpointType == simpleEndpoint)
    {
        return mctp_server::BindingModeTypes::Endpoint;
    }
    else if (endpointType == busOwnerBridge)
    {
        // TODO: need to differentiate between BusOwner and Bridge
        return mctp_server::BindingModeTypes::Bridge;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid endpoint type value");
        throw;
    }
}

MsgTypes MCTPDevice::getMsgTypes(const std::vector<uint8_t>& msgType)
{
    MsgTypes messageTypes;

    for (auto type : msgType)
    {
        switch (type)
        {
            case MCTP_MESSAGE_TYPE_MCTP_CTRL: {
                messageTypes.mctpControl = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_PLDM: {
                messageTypes.pldm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NCSI: {
                messageTypes.ncsi = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_ETHERNET: {
                messageTypes.ethernet = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_NVME: {
                messageTypes.nvmeMgmtMsg = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_SPDM: {
                messageTypes.spdm = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDPCI: {
                messageTypes.vdpci = true;
                break;
            }
            case MCTP_MESSAGE_TYPE_VDIANA: {
                messageTypes.vdiana = true;
                break;
            }
            default: {
                // TODO: Add OEM Message Type support
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid message type");
                break;
            }
        }
    }
    return messageTypes;
}

std::optional<mctp_eid_t> MCTPDevice::getEIDFromUUID(const std::string& uuidStr)
{
    for (const auto& [eid, deviceUUID] : uuidTable)
    {
        if (uuidStr.compare(deviceUUID) == 0)
        {
            return eid;
        }
    }
    return std::nullopt;
}

bool MCTPDevice::isEIDMappedToUUID(const mctp_eid_t eid,
                                   const std::string& destUUID)
{
    std::optional<mctp_eid_t> eidFromTable = getEIDFromUUID(destUUID);
    if (eidFromTable.has_value())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("EID from table " + std::to_string(eidFromTable.value())).c_str());
        if (eid == eidFromTable.value())
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Endpoint already Registered with EID " + std::to_string(eid))
                    .c_str());
            return true;
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Endpoint needs re-registration. EID from device:" +
             std::to_string(eid) +
             " EID from table:" + std::to_string(eidFromTable.value()))
                .c_str());
    }
    return false;
}

std::optional<mctp_eid_t>
    MCTPDevice::getEIDForReregistration(const std::string& destUUID)
{
    if (auto eidFromTable = getEIDFromUUID(destUUID))
    {
        unregisterEndpoint(eidFromTable.value());
        // Give priority for EID from UUID table while re-registering
        return eidFromTable.value();
    }
    return std::nullopt;
}

bool MCTPDevice::isMCTPVersionSupported(const MCTPVersionFields& version)
{
    if ((version.major == supportedMCTPVersion.major) &&
        (version.minor == supportedMCTPVersion.minor) &&
        (version.update == supportedMCTPVersion.update))
    {
        return true;
    }
    return false;
}

bool MCTPDevice::isEIDRegistered(mctp_eid_t eid)
{
    if (endpointInterface.count(eid) > 0)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Endpoint already Registered with EID " + std::to_string(eid))
                .c_str());
        return true;
    }

    return false;
}

void MCTPDevice::unregisterEndpoint(mctp_eid_t eid)
{
    bool epIntf = removeInterface(eid, endpointInterface);
    bool msgTypeIntf = removeInterface(eid, msgTypeInterface);
    bool uuidIntf = removeInterface(eid, uuidInterface);
    // Vendor ID interface is optional thus not considering return status
    removeInterface(eid, vendorIdInterface);
    removeInterface(eid, locationCodeInterface);
    removeInterface(eid, deviceInterface);

    if (epIntf && msgTypeIntf && uuidIntf)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            ("Device Unregistered: EID = " + std::to_string(eid)).c_str());
    }
    routingTable.removeEntry(eid);
}
