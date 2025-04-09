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

#include "MCTPBinding.hpp"

#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"
#include "unix_sock_intf.hpp"
#include "utils/dbus_helper.hpp"
#include "utils/utils.hpp"

#include <systemd/sd-id128.h>

#include <phosphor-logging/log.hpp>

#include "libmctp-msgtypes.h"

constexpr sd_id128_t mctpdAppId = SD_ID128_MAKE(c4, e4, d9, 4a, 88, 43, 4d, f0,
                                                94, 9d, bb, 0a, af, 53, 4e, 6d);

/* According DSP0239(Version: 1.7.0) */
static const std::unordered_map<uint8_t,
                                mctp_server::MctpPhysicalMediumIdentifiers>
    valueToMediumId = {
        /*0x00 Unspecified*/
        {0x01,
         mctp_server::MctpPhysicalMediumIdentifiers::Smbus}, /*SMBus 2.0 100 kHz
                                                                compatible*/
        {0x02, mctp_server::MctpPhysicalMediumIdentifiers::
                   SmbusI2c}, /*SMBus 2.0 + I2C 100 kHz compatible*/
        {0x03, mctp_server::MctpPhysicalMediumIdentifiers::
                   I2cCompatible}, /*I2C 100 kHz compatible (Standard-mode)*/
        {0x04, mctp_server::MctpPhysicalMediumIdentifiers::
                   Smbus3OrI2c400khzCompatible}, /*SMBus 3.0 or I2C 400 kHz
                                                    compatible (Fast-mode)*/
        {0x05, mctp_server::MctpPhysicalMediumIdentifiers::
                   Smbus3OrI2c1MhzCompatible}, /*SMBus 3.0 or I2C 1 MHz
                                                  compatible (Fast-mode Plus)*/
        {0x06,
         mctp_server::MctpPhysicalMediumIdentifiers::
             I2c3Mhz4Compatible}, /*I2C 3.4 MHz compatible (High-speed mode)*/
        /*0x07 Reserved*/
        {0x08, mctp_server::MctpPhysicalMediumIdentifiers::
                   Pcie11}, /*PCIe revision 1.1 compatible*/
        {0x09,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie2}, /*PCIe revision 2.0
                                                                compatible*/
        {0x0A, mctp_server::MctpPhysicalMediumIdentifiers::
                   Pcie21}, /*PCIe revision 2.1 compatible*/
        {0x0B,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie3}, /*PCIe revision 3.x
                                                                compatible*/
        {0x0C,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie4}, /*PCIe revision 4.x
                                                                compatible*/
        {0x0D,
         mctp_server::MctpPhysicalMediumIdentifiers::Pcie5}, /*PCIe revision 5.x
                                                                compatible*/
        /*0x0E Reserved*/
        {0x0F, mctp_server::MctpPhysicalMediumIdentifiers::
                   PciCompatible}, /*PCI compatible
                                      (PCI 1.0,2.0,2.1,2.2,2.3,3.0,PCI-X 1.0,
                                      PCI-X 2.0)*/
        {0x10, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb11Compatible}, /*USB 1.1 compatible*/
        {0x11, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb20Compatible}, /*USB 2.0 compatible*/
        {0x12, mctp_server::MctpPhysicalMediumIdentifiers::
                   Usb30Compatible}, /*USB 3.0 compatible*/
        /*0x13:0x17 Reserved*/
        {0x18, mctp_server::MctpPhysicalMediumIdentifiers::
                   NcSiOverRbt}, /*NC-SI over RBT (A physical interface based on
                                    RMII as defined inDSP0222)*/
        /*0x19:0x1F Reserved*/
        {0x20, mctp_server::MctpPhysicalMediumIdentifiers::
                   KcsLegacy}, /*KCS / Legacy (Fixed Address Decoding)*/
        {0x21, mctp_server::MctpPhysicalMediumIdentifiers::
                   KcsPci}, /*KCS / PCI (Base Class 0xC0 Subclass 0x01)*/
        {0x22, mctp_server::MctpPhysicalMediumIdentifiers::
                   SerialHostLegacy}, /*Serial Host / Legacy (Fixed Address
                                         Decoding)*/
        {0x23, mctp_server::MctpPhysicalMediumIdentifiers::
                   SerialHostPci}, /*Serial Host / PCI (Base Class 0x07 Subclass
                                      0x00)*/
        {0x24,
         mctp_server::MctpPhysicalMediumIdentifiers::
             AsynchronousSerial}, /*Asynchronous Serial3(Between MCs and IMDs)*/
        {0x30, mctp_server::MctpPhysicalMediumIdentifiers::
                   I3cSDR}, /*I3C 12.5 MHz compatible (SDR)*/
        {0x31, mctp_server::MctpPhysicalMediumIdentifiers::
                   I3cHDRDDR} /*I3C 25 MHz compatible (HDR-DDR)*/
                              /*0x32:0x3F Reserved */
                              /*0x40, CXL 1.x*/
                              /*0x41:0xFF Reserved*/
};

MctpBinding::MctpBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                         std::shared_ptr<object_server>& objServer,
                         const std::string& objPath, const Configuration& conf,
                         boost::asio::io_context& ioc,
                         const mctp_server::BindingTypes bindingType) :
    MCTPBridge(conn, ioc, objServer), regInProgress(ioc),
    bindingID(bindingType), localSocketEp(unix_ipc::unix_path::getSockPath()),
    acceptor(ioc, localSocketEp), networkId(conf.networkId)

{
    objServer->add_manager(objPath);
    mctpServiceScanner.setAllowedBuses(conf.allowedBuses.begin(),
                                       conf.allowedBuses.end());

    mctpServiceScanner.setCallback(
        [this](bridging::MCTPServiceScanner::EndPoint ep, bool isHotplugged) {
            if (routingTable.contains(ep.eid))
            {
                // Entry detcted from this process itself. Ignore
                return;
            }

            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("New EID " + std::to_string(ep.eid) + " of type " +
                 ep.endpointType +
                 (isHotplugged ? " hotplugged" : " existing") + " on " +
                 ep.service.name)
                    .c_str());

            // TODO. Get physical medium specific details
            auto entryType = mctpd::convertToEndpointType(ep.endpointType);
            mctpd::RoutingTable::Entry entry(
                ep.eid, ep.service.name, entryType, ep.mediumTypeId,
                ep.transportTypeId, ep.physicalAddress);
            entry.isUpstream = true;
            routingTable.updateEntry(ep.eid, entry);
            sendNewRoutingTableEntryToAllBridges(entry);
        });
    mctpServiceScanner.setEidRemovedCallback(
        [this](bridging::MCTPServiceScanner::EndPoint ep) {
            if (this->routingTable.removeEntry(ep.eid))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    (std::to_string(ep.eid) + " removed from routing table")
                        .c_str());
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    (std::to_string(ep.eid) + " was not in routing table")
                        .c_str());
            }
        });

    mctpServiceScanner.setNewServiceCallback(
        std::bind(&MctpBinding::onNewService, this, std::placeholders::_1));

    mctpInterface = objServer->add_interface(objPath, mctp_server::interface);
    uuidIntface =
        objServer->add_interface(objPath, "xyz.openbmc_project.Common.UUID");
    /*initialize the map*/
    versionNumbersForUpperLayerResponder.emplace(
        MCTP_MESSAGE_TYPE_MCTP_CTRL,
        std::vector<version_entry>{{0xF1, 0xF3, 0xF1, 0}});
    versionNumbersForUpperLayerResponder.emplace(
        MCTP_GET_VERSION_SUPPORT_BASE_INFO,
        std::vector<version_entry>{{0xF1, 0xF3, 0xF1, 0}});

    try
    {
        ownEid = conf.defaultEid;
        bindingMediumID = conf.mediumId;
        bindingModeType = conf.mode;
        supportsBridge = conf.supportsBridge;

        ctrlTxRetryDelay = conf.reqToRespTime;
        ctrlTxRetryCount = conf.reqRetryCount;

        supportsSPDMRequester = conf.supportsSPDMRequester;

        createUuid();
        registerProperty(uuidIntface, "UUID", uuid);

        registerProperty(mctpInterface, "Eid", ownEid);

        registerProperty(mctpInterface, "StaticEid", staticEid);

        registerProperty(mctpInterface, "BindingID",
                         mctp_server::convertBindingTypesToString(bindingID));
        registerProperty(mctpInterface, "SocketPath",
                         unix_ipc::unix_path::getPIDStr());

        registerProperty(
            mctpInterface, "BindingMediumID",
            mctp_server::convertMctpPhysicalMediumIdentifiersToString(
                bindingMediumID));

        registerProperty(
            mctpInterface, "BindingMode",
            mctp_server::convertBindingModeTypesToString(bindingModeType));

        registerProperty(mctpInterface, "NetworkID", conf.networkId);

        setupSecureTelemetryEnableMatch();
        getSecureTelemetryEnableProperty();

        /*
         * msgTag and tagOwner are not currently used, but can't be removed
         * since they are defined for SendMctpMessagePayload() in the current
         * version of MCTP D-Bus interface.
         */
        mctpInterface->register_method(
            "SendMctpMessagePayload",
            [this](uint8_t dstEid, uint8_t msgTag, bool tagOwner,
                   std::vector<uint8_t> payload) {
                return this->sendMctpMessagePayload(dstEid, msgTag, tagOwner,
                                                    payload);
            });

        mctpInterface->register_method(
            "ReserveBandwidth",
            [this](boost::asio::yield_context yield, const mctp_eid_t eid,
                   const uint16_t timeout) {
                if (!reserveBandwidth(yield, eid, timeout))
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        ("Reserve bandwidth failed for EID: " +
                         std::to_string(eid))
                            .c_str());
                    return static_cast<int>(mctpErrorRsvBWFailed);
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Reserve bandwidth is active for EID: " +
                     std::to_string(eid))
                        .c_str());
                return static_cast<int>(mctpSuccess);
            });

        mctpInterface->register_method(
            "SkipList", [this](std::vector<uint8_t> payload) {
                if (!skipListPath(payload))
                {
                    phosphor::logging::log<phosphor::logging::level::WARNING>(
                        "SkipList is failed");
                    return static_cast<int>(mctpInternalError);
                }
                return static_cast<int>(mctpSuccess);
            });

        mctpInterface->register_method(
            "ReleaseBandwidth",
            [this](boost::asio::yield_context yield, const mctp_eid_t eid) {
                if (!releaseBandwidth(yield, eid))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("Release bandwidth failed for EID: " +
                         std::to_string(eid))
                            .c_str());
                    return static_cast<int>(mctpErrorReleaseBWFailed);
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("Bandwidth released for EID: " + std::to_string(eid))
                        .c_str());
                return static_cast<int>(mctpSuccess);
            });
        mctpInterface->register_method(
            "SendReceiveMctpMessagePayload",
            [this](boost::asio::yield_context yield, uint8_t dstEid,
                   std::vector<uint8_t> payload,
                   uint16_t timeout) -> std::vector<uint8_t> {
                auto [error, resp] = this->sendReceiveMctpMessagePayload(
                    yield, dstEid, payload, timeout);
                if (error)
                {
                    throw std::system_error(error);
                }
                return resp;
            });

        mctpInterface->register_signal<uint8_t, uint8_t, uint8_t, bool,
                                       std::vector<uint8_t>>(
            "MessageReceivedSignal");

        mctpInterface->register_method(
            "RegisterResponder",
            [this](uint8_t msgTypeName,
                   std::vector<uint8_t> inputVersion) -> bool {
                return registerUpperLayerResponder(msgTypeName, inputVersion);
            });

        mctpInterface->register_method(
            "SetEIDPool", [this](uint8_t startEID, uint8_t poolSize) -> bool {
                return this->setEIDPool(startEID, poolSize);
            });

        // register VDPCI responder with MCTP for upper layers
        mctpInterface->register_method(
            "RegisterVdpciResponder",
            [this](uint16_t vendorIdx, uint16_t cmdSetType,
                   [[maybe_unused]] std::vector<uint8_t> inputVersion) -> bool {
                // TODO . Use inputVersion to set support for VDPCI type using
                // registerUpperLayerResponder
                return manageVdpciVersionInfo(vendorIdx, cmdSetType);
            });

        mctpInterface->register_method("TriggerDeviceDiscovery",
                                       [this]() { triggerDeviceDiscovery(); });

        mctpInterface->register_method(
            "SendMctpRawPayload", [this](const std::vector<uint8_t>& data) {
                return static_cast<int>(this->sendMctpRawPayload(data));
            });

        mctpInterface->register_method(
            "InitiateHandshake",
            [this](const uint32_t deviceEid, const bool connState) {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    (" deviceEid: " + std::to_string(deviceEid)).c_str());

                if (connState)
                {
                    // Insert the deviceEid if connState is true
                    this->sessionSet.insert(deviceEid);
                }
                else
                {
                    // Remove the deviceEid if connState is false
                    auto it = this->sessionSet.find(deviceEid);
                    if (it != this->sessionSet.end())
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            ("Removing EID from sessionSet - " +
                             std::to_string(deviceEid))
                                .c_str());
                        this->sessionSet.erase(it);
                    }
                }
            });

        if (mctpInterface->initialize() == false ||
            uuidIntface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP Interface initialization failed.",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

void MctpBinding::setupSecureTelemetryEnableMatch()
{
    if (secureTelemetryEnableMatch)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unable to setup SecureTelemetryEnable match");
        return;
    }

    std::string matchString =
        sdbusplus::bus::match::rules::type::signal() +
        sdbusplus::bus::match::rules::interface(
            "org.freedesktop.DBus.Properties") +
        sdbusplus::bus::match::rules::path("/xyz/openbmc_project/secure/pfr") +
        sdbusplus::bus::match::rules::member("PropertiesChanged") +
        sdbusplus::bus::match::rules::argN(
            0, "xyz.openbmc_project.PFR.Attributes");
    try
    {
        secureTelemetryEnableMatch =
            std::make_unique<sdbusplus::bus::match::match>(
                static_cast<sdbusplus::bus::bus&>(*connection), matchString,
                [this](sdbusplus::message::message& message) {
                    std::string interfaceName;
                    std::map<std::string, std::variant<bool, std::string>>
                        changedProperties;
                    std::vector<std::string> invalidatedProperties;

                    message.read(interfaceName, changedProperties,
                                 invalidatedProperties);

                    auto findProperty =
                        changedProperties.find("SecureTelemetryEnable");
                    if (findProperty == changedProperties.end())
                    {
                        return;
                    }

                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        "SecureTelemetryEnable property changed");

                    bool secureTelemetryEnable =
                        std::get<bool>(findProperty->second);

                    // Update the variable in mctpd
                    MctpBinding::secureTelemetryEnable = secureTelemetryEnable;

                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        ("SecureTelemetryEnable is now " +
                         std::to_string(secureTelemetryEnable))
                            .c_str());
                });
    }

    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to setup SecureTelemetryEnable match",
            phosphor::logging::entry("ERROR=%s", e.what()));
    }
}

void MctpBinding::getSecureTelemetryEnableProperty()
{
    connection->async_method_call(
        [this](boost::system::error_code ec,
               const std::variant<bool>& propertyValue) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to get SecureTelemetryEnable property");
                return;
            }

            secureTelemetryEnable = std::get<bool>(propertyValue);
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("SecureTelemetryEnable property value: " +
                 std::to_string(secureTelemetryEnable))
                    .c_str());
        },
        "xyz.openbmc_project.Secure.PFR.Manager",
        "/xyz/openbmc_project/secure/pfr", "org.freedesktop.DBus.Properties",
        "Get", "xyz.openbmc_project.PFR.Attributes", "SecureTelemetryEnable");
}

/*
 * Comment out unused parameters since rxMessage is a callback
 * passed to libmctp and we have to match its expected prototype.
 */
void MctpBinding::rxMessage(uint8_t srcEid, void* data, void* msg, size_t len,
                            bool tagOwner, uint8_t msgTag, void* bindingPrivate)
{
    if (msg == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MCTP Receive Message is not initialized.");
        return;
    }

    if (data == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Null data received");
        return;
    }

    uint8_t* payload = reinterpret_cast<uint8_t*>(msg);
    uint8_t msgType = payload[0]; // Always the first byte
    std::vector<uint8_t> response;

    response.assign(payload, payload + len);

    auto& binding = *static_cast<MctpBinding*>(data);

    if (binding.bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        binding.addUnknownEIDToDeviceTable(srcEid, bindingPrivate);
    }

    // TODO: Take into account the msgTags too when we verify control messages.
    if (!tagOwner && mctp_is_mctp_ctrl_msg(msg, len) &&
        !mctp_ctrl_msg_is_req(msg, len))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "MCTP Control packet response received!!");
        if (binding.handleCtrlResp(msg, len))
        {
            return;
        }
    }

    //  Decryption should be considered only if message is encrypted
    uint32_t deviceId = binding.createDeviceId(srcEid, binding.networkId);
    auto useDbus = binding.checkSession(deviceId);
    std::vector<uint8_t> decryptedPayload;
    if (secureTelemetryEnable && useDbus &&
        msgType == MCTP_MESSAGE_TYPE_SECUREDMSG)
    {
        binding.decryptPayloadUsingDBus(binding.networkId, srcEid, response,
                                        decryptedPayload);
        if (decryptedPayload.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Decryption failed for EID=%d",
                phosphor::logging::entry("EID=%d", srcEid));
            return;
        }
        else
        {
            response = std::move(
                decryptedPayload); // Update the response with decrypted data
        }
    }

    if (!tagOwner &&
        binding.transmissionQueue.receive(binding.mctp, srcEid, msgTag,
                                          std::move(response), binding.io))
    {
        return;
    }
    unix_ipc::broadCastAll(response, srcEid);
    auto msgSignal = binding.connection->new_signal("/xyz/openbmc_project/mctp",
                                                    mctp_server::interface,
                                                    "MessageReceivedSignal");
    msgSignal.append(msgType, srcEid, msgTag, tagOwner, response);
    msgSignal.signal_send();
}

void MctpBinding::handleMCTPControlRequests(uint8_t srcEid, void* data,
                                            void* msg, size_t len,
                                            bool tagOwner, uint8_t msgTag,
                                            void* bindingPrivate)
{
    /*
     * We only check the msg pointer, private data may be unused by some
     * bindings.
     */
    if (msg == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "MCTP Control Message is not initialized.");
        return;
    }

    if (data == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Null data received");
        return;
    }

    if (!tagOwner)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "MCTP Control Message expects that tagOwner is set");
        return;
    }
    auto& binding = *static_cast<MctpBinding*>(data);

    if (binding.bindingModeType == mctp_server::BindingModeTypes::Endpoint)
    {
        binding.addUnknownEIDToDeviceTable(srcEid, bindingPrivate);
    }

    binding.handleCtrlReq(srcEid, bindingPrivate, msg, len, msgTag);
}

bool MctpBinding::reserveBandwidth(boost::asio::yield_context /*yield*/,
                                   const mctp_eid_t /*eid*/,
                                   const uint16_t /*timeout*/)
{
    return true;
}

bool MctpBinding::releaseBandwidth(boost::asio::yield_context /*yield*/,
                                   const mctp_eid_t /*eid*/)
{
    return true;
}

void MctpBinding::triggerDeviceDiscovery()
{
}

bool MctpBinding::registerUpperLayerResponder(uint8_t typeNo,
                                              std::vector<uint8_t>& versionData)
{
    bool ret = false;
    switch (typeNo)
    {
        case MCTP_MESSAGE_TYPE_PLDM:
        case MCTP_MESSAGE_TYPE_NCSI:
        case MCTP_MESSAGE_TYPE_ETHERNET:
        case MCTP_MESSAGE_TYPE_NVME:
        case MCTP_MESSAGE_TYPE_SPDM:
        case MCTP_MESSAGE_TYPE_CXL_FM_API:
        case MCTP_MESSAGE_TYPE_CXL_CCI:
        case MCTP_MESSAGE_TYPE_SECUREDMSG:
            ret = manageVersionInfo(typeNo, versionData);
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid Type for Registration To MCTP");
            break;
    }
    return ret;
}

bool MctpBinding::manageVersionInfo(uint8_t typeNo,
                                    std::vector<uint8_t>& versionInfo)
{
    if (versionInfo.empty() || versionInfo.size() % sizeof(version_entry) != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "The Version info is of invalid length...");
        return false;
    }

    if (versionNumbersForUpperLayerResponder.find(typeNo) ==
        versionNumbersForUpperLayerResponder.end())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No existing Data for typeNo, So pushing into map");

        std::vector<version_entry> verString(versionInfo.size() /
                                             sizeof(version_entry));
        std::copy_n(versionInfo.begin(), versionInfo.size(),
                    reinterpret_cast<uint8_t*>(verString.data()));

        versionNumbersForUpperLayerResponder.emplace(typeNo, verString);
        return true;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Existing Data In Map for the typeNo");
    return false;
}

bool MctpBinding::manageVdpciVersionInfo(uint16_t vendorIdx,
                                         uint16_t cmdSetType)
{
    struct InternalVdmSetDatabase vdmSupport;

    auto retIter = std::find_if(vdmSetDatabase.begin(), vdmSetDatabase.end(),
                                [vendorIdx](const InternalVdmSetDatabase& vm) {
                                    return vm.vendorId == vendorIdx;
                                });

    if (retIter == vdmSetDatabase.end())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No existing Data for vendorId, So pushing into map");

        vdmSupport.vendorId = vendorIdx;
        vdmSupport.commandSetType = cmdSetType;
        vdmSupport.vendorIdFormat = 0; // 0x00 for VDPCI.
        vdmSetDatabase.push_back(vdmSupport);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "existing Data for vendorId, So updating into map");
        if (retIter->commandSetType != cmdSetType)
        { /*may be the details need to be updated*/
            retIter->vendorId = vendorIdx;
            retIter->commandSetType = cmdSetType;
            retIter->vendorIdFormat = 0; // 0x00 for VDPCI
        }
    }

    return true;
}

void MctpBinding::createUuid()
{
    sd_id128_t id;
    guid_t uuidStr;
    if (sd_id128_get_machine_app_specific(mctpdAppId, &id))
    {
        throw std::system_error(
            std::make_error_code(std::errc::address_not_available));
    }
    std::copy(std::begin(id.bytes), std::end(id.bytes),
              std::begin(uuidStr.raw));
    uuid = formatUUID(uuidStr);
}

void MctpBinding::initializeMctp()
{
    mctpServiceScanner.scan();
    addOwnEIDToRoutingTable();
}

bool MctpBinding::setMediumId(
    uint8_t value, mctp_server::MctpPhysicalMediumIdentifiers& mediumId)
{
    auto id = valueToMediumId.find(value);
    if (id != valueToMediumId.end())
    {
        mediumId = id->second;
        return true;
    }
    return false;
}

/* This api provides option to register an endpoint using the binding
 * private data. The callers of this api can parallelize multiple
 * endpoint registrations by spawning coroutines and passing yield contexts.*/

std::optional<mctp_eid_t>
    MctpBinding::registerEndpoint(boost::asio::yield_context& yield,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  mctp_eid_t eid,
                                  mctp_server::BindingModeTypes bindingMode)
{
    if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
    {
        EndpointProperties epProperties;
        std::optional<mctp_eid_t> destEID =
            busOwnerRegisterEndpoint(yield, bindingPrivate, eid, epProperties);

        // Handle the device if removed and the device reset due to Frimware
        // update/hot plugged.
        if (!destEID)
        {
            clearRegisteredDevice(eid);
        }
        return destEID;
    }

    MsgTypeSupportCtrlResp msgTypeSupportResp;
    if (!(getMsgTypeSupportCtrlCmd(yield, bindingPrivate, eid,
                                   &msgTypeSupportResp)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get Message Type Support failed");
        return std::nullopt;
    }

    // check if EID is already registered
    if (endpointInterface.find(eid) != endpointInterface.end())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("EID " + std::to_string(eid) + " is already registered").c_str());
        return std::nullopt;
    }

    EndpointProperties epProperties;
    std::vector<uint8_t> getUuidResp;

    if (!(getUuidCtrlCmd(yield, bindingPrivate, eid, getUuidResp)))
    {
        /* In case EP doesn't support Get UUID set to all 0 */
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get UUID failed");
        epProperties.uuid = "00000000-0000-0000-0000-000000000000";
    }
    else
    {
        mctp_ctrl_resp_get_uuid* getUuidRespPtr =
            reinterpret_cast<mctp_ctrl_resp_get_uuid*>(getUuidResp.data());
        epProperties.uuid = formatUUID(getUuidRespPtr->uuid);
    }

    epProperties.endpointEid = eid;
    epProperties.mode = bindingMode;
    // TODO:get Network ID, now set it to 0
    epProperties.networkId = 0x00;
    epProperties.endpointMsgTypes = getMsgTypes(msgTypeSupportResp.msgType);

    getVendorDefinedMessageTypes(yield, bindingPrivate, eid, epProperties);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Device Registered: EID = " + std::to_string(eid)).c_str());
    auto endpointType = mctpd::convertToEndpointType(bindingMode);
    uint8_t mediumId = static_cast<uint8_t>(
        mctpd::convertToPhysicalMediumIdentifier(bindingMediumID));

    mctpd::RoutingTable::Entry entry(eid, getDbusName(), endpointType, mediumId,
                                     getTransportId(),
                                     getPhysicalAddress(bindingPrivate));
    routingTable.updateEntry(eid, entry);

    if (bindingModeType != mctp_server::BindingModeTypes::Endpoint)
    {
        // Inform all downstream bridges about the new device
        sendNewRoutingTableEntryToAllBridges(entry);
        if (mctpd::isBridge(endpointType))
        {
            // Newly added device is a bridge. Send current routing table to it.
            sendRoutingTableEntriesToBridge(eid, bindingPrivate);
        }
    }

    populateDeviceProperties(eid, bindingPrivate);
    populateEndpointProperties(epProperties);

    return eid;
}

void MctpBinding::clearRegisteredDevice(const mctp_eid_t eid)
{
    // Remove the entry from uuidTable, unregister the device and return EID to
    // the pool.
    uuidTable.erase(eid);
    unregisterEndpoint(eid);
    eidPool.updateEidStatus(eid, false);
}

void MctpBinding::addUnknownEIDToDeviceTable(const mctp_eid_t, void*)
{
    // Do nothing
}

// Send raw payload starting from MCTP header.
MctpStatus MctpBinding::sendMctpRawPayload(const std::vector<uint8_t>& payload)
{
    static constexpr size_t minMctpMessageSize = 5;
    if (payload.size() < minMctpMessageSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SendMctpRawPayload: Expects at least 5 bytes in mctp message");
        return mctpInternalError;
    }
    else
    {
        std::stringstream ss;
        ss << "Bridging packet: [";
        for (int byte : payload)
        {
            ss << byte << ',';
        }
        ss << ']';
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ss.str().c_str());
    }

    // Destination EID is in byte 1.
    mctp_eid_t dstEid = payload[1];
    mctp_eid_t srcEid = payload[2];

    if (!routingTable.contains(srcEid))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SendMctpRawPayload: Invalid source EID " + std::to_string(srcEid))
                .c_str());
        return mctpInternalError;
    }

    MctpStatus status = mctpInternalError;
    try
    {
        auto& entry = routingTable.getEntry(dstEid);

        // If downstream device then do the physical transmission
        if (!entry.isUpstream)
        {
            if (rsvBWActive && dstEid != reservedEID)
            {
                status = mctpErrorOperationNotAllowed;
                throw std::runtime_error(
                    (("Send is not allowed. ReserveBandwidth is active "
                      "for ") +
                     std::to_string(reservedEID))
                        .c_str());
            }

            std::optional<std::vector<uint8_t>> pvtData =
                getBindingPrivateData(dstEid);
            if (!pvtData)
            {
                status = mctpInternalError;
                throw std::runtime_error(
                    "SendMctpRawPayload: Invalid destination EID");
            }

            if (mctp_message_raw_tx(mctp, payload.data(), payload.size(),
                                    pvtData->data()) < 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error while doing mctp raw tx");
                status = mctpInternalError;
            }
            else
            {
                status = mctpSuccess;
            }
        }
        else
        {
            // Upstream device. Pass the payload to destination mctpd service.
            auto sendCB = [dstEid](boost::system::error_code ec,
                                   int sendStatus) {
                if (ec || sendStatus != 0)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        (std::string("Error bridging raw message. ") +
                         ec.message())
                            .c_str(),
                        phosphor::logging::entry("EID=%d", dstEid));
                }
            };
            connection->async_method_call(
                sendCB, entry.serviceName, "/xyz/openbmc_project/mctp",
                "xyz.openbmc_project.MCTP.Base", "SendMctpRawPayload", payload);
            status = mctpSuccess;
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
    }
    return status;
}

// Bridging packets destined to other mctpd services will reach this function
void MctpBinding::onRawMessage(void* data, void* msg, size_t len,
                               void* /*msgBindingPrivate*/)
{
    if (nullptr == data || nullptr == msg)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Bridging packet or binding private is null while doing bridging");
        return;
    }
    uint8_t* mctpData = static_cast<uint8_t*>(msg);
    std::vector<uint8_t> payload(mctpData, mctpData + len);
    auto binding = static_cast<MctpBinding*>(data);

    // sendMctpRawPayload will find the destination and do the transfer
    binding->sendMctpRawPayload(payload);
}

bool MctpBinding::setEIDPool(const uint8_t startEID, const uint8_t poolSize)
{
    if (bindingModeType != mctp_server::BindingModeTypes::BusOwner)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Not a busowner to accept eid pool");
        return false;
    }

    if (startEID > (0xFF - poolSize))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Invalid EID range passed to us");
        return false;
    }
    std::set<mctp_eid_t> eidRange;

    for (uint8_t i = startEID; i < (startEID + poolSize); i++)
    {
        eidRange.insert(i);
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("Setting EID pool " + std::to_string(startEID) + " + " +
         std::to_string(poolSize))
            .c_str());

    (void)boost::asio::spawn(
        io,
        [this, eidRange](boost::asio::yield_context yield) {
            auto lock = regInProgress.lock(yield, regTimeout);

            eidPool.clearEIDPool();
            eidPool.initializeEidPool(eidRange);

            onEIDPool();
        },
        {});

    return true;
}

bool MctpBinding::skipListPath(std::vector<uint8_t> /*payload*/)
{
    return false;
}

void MctpBinding::onNewService(const std::string& service)
{
    auto isInPoolDist =
        downstreamEIDPools.find(service) != downstreamEIDPools.end();
    if (!isInPoolDist)
    {
        return;
    }

    (void)boost::asio::spawn(
        this->connection->get_io_context(),
        [this, service](boost::asio::yield_context yield) {
            constexpr std::chrono::milliseconds dbusDelay(200);
            boost::asio::steady_timer setEIDPoolTimer(
                connection->get_io_context());
            boost::system::error_code ec;

            setEIDPoolTimer.expires_after(dbusDelay);
            setEIDPoolTimer.async_wait(yield[ec]);

            if (ec)
            {
                // Timer exited abruptly.
                return;
            }

            if (!passEIDPoolTo(yield, service))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "SetEID pool returned false from service callback");
            }
        },
        {});
}

void MctpBinding::onEIDPool()
{
}

MctpBinding& MctpBinding::getPtr()
{
    return *this;
}

bool MctpBinding::checkSession(uint32_t deviceId)
{
    return sessionSet.find(deviceId) != sessionSet.end();
}

uint32_t MctpBinding::createDeviceId(uint8_t mctpEid, uint8_t networkId)
{
    return (static_cast<uint32_t>(networkId) << 8) | mctpEid;
}

void MctpBinding::encryptPayloadUsingDBus(
    uint8_t networkId, uint8_t dstEid, const std::vector<uint8_t>& inputPayload,
    std::vector<uint8_t>& encryptedPayload)
{
    std::string objectPath = "/com/intel/spdmd_secure_session/device/" +
                             std::to_string(networkId) + "/" +
                             std::to_string(dstEid);
    std::string serviceName = "com.intel.spdmd.secure.session";
    std::string interfaceName = "com.intel.spdmd_secure_session.spdm_device";
    std::string methodName = "EncryptMessagePayload";

    auto msg =
        connection->new_method_call(serviceName.c_str(), objectPath.c_str(),
                                    interfaceName.c_str(), methodName.c_str());
    msg.append(inputPayload);

    try
    {
        auto reply = connection->call(msg);
        reply.read(encryptedPayload);
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Encryption successful.");
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to encrypt payload via D-Bus for Device ID: " +
             std::to_string((networkId << 8) | dstEid) + ", ERROR=" + e.what())
                .c_str());
        encryptedPayload.clear();
    }
}

void MctpBinding::decryptPayloadUsingDBus(
    uint8_t networkId, uint8_t dstEid, const std::vector<uint8_t>& inputPayload,
    std::vector<uint8_t>& decryptedPayload)
{
    std::string objectPath = "/com/intel/spdmd_secure_session/device/" +
                             std::to_string(networkId) + "/" +
                             std::to_string(dstEid);
    std::string serviceName = "com.intel.spdmd.secure.session";
    std::string interfaceName = "com.intel.spdmd_secure_session.spdm_device";
    std::string methodName = "DecryptMessagePayload";

    auto msg =
        connection->new_method_call(serviceName.c_str(), objectPath.c_str(),
                                    interfaceName.c_str(), methodName.c_str());
    msg.append(inputPayload);

    try
    {
        auto reply = connection->call(msg);
        reply.read(decryptedPayload);
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Decryption successful.");
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("Failed to decrypt payload via D-Bus for Device ID: " +
             std::to_string((networkId << 8) | dstEid) + ", ERROR=" + e.what())
                .c_str());
        decryptedPayload.clear();
    }
}

void MctpBinding::acceptConnections()
{
    acceptor.async_accept(
        localSocketEp,
        [this](boost::system::error_code ec,
               boost::asio::local::stream_protocol::socket socket) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Upper layer Application failed to connect");
            }
            else
            {
                auto sesn = std::make_shared<unix_ipc::Session>(
                    std::move(socket), this->connection->get_io_context(),
                    getPtr(), ++socketConnCount);
                sesn->run();
                unix_ipc::addSessionToList(socketConnCount, sesn);
            }
            acceptConnections();
        });
}

std::pair<std::error_code, std::vector<uint8_t>>
    MctpBinding::sendReceiveMctpMessagePayload(boost::asio::yield_context yield,
                                               uint8_t dstEid,
                                               std::vector<uint8_t>& payload,
                                               uint16_t timeout)
{
    if (rsvBWActive && dstEid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (("SendReceiveMctpMessagePayload is not allowed. "
              "ReserveBandwidth is "
              "active for EID: ") +
             std::to_string(reservedEID))
                .c_str());
        return std::make_pair(std::make_error_code(std::errc::invalid_argument),
                              std::vector<uint8_t>{});
    }
    uint8_t msgType = payload[0]; // Always the first byte
    if (payload.size() > 0)
    {

        if (msgType == MCTP_MESSAGE_TYPE_MCTP_CTRL)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Transmiting control message");
        }
    }

    std::optional<std::vector<uint8_t>> pvtData = getBindingPrivateData(dstEid);
    if (!pvtData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SendReceiveMctpMessagePayload: Invalid destination "
            "EID");
        return std::make_pair(std::make_error_code(std::errc::invalid_argument),
                              std::vector<uint8_t>{});
    }

    std::vector<uint8_t> encryptedPayload;
    uint32_t deviceId = createDeviceId(dstEid, networkId);
    auto useDbus = checkSession(deviceId);

    if (secureTelemetryEnable && useDbus &&
        msgType != MCTP_MESSAGE_TYPE_MCTP_CTRL &&
        msgType != MCTP_MESSAGE_TYPE_SECUREDMSG &&
        msgType != MCTP_MESSAGE_TYPE_SPDM)
    {
        encryptPayloadUsingDBus(networkId, dstEid, payload, encryptedPayload);
        if (encryptedPayload.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Encryption failed");
            return std::make_pair(
                std::make_error_code(std::errc::connection_aborted),
                std::vector<uint8_t>{});
        }
        else
        {
            payload =
                std::move(encryptedPayload); // Use encrypted payload only if
                                             // encryption was successful
        }
    }

    boost::system::error_code ec;
    auto message = transmissionQueue.transmit(mctp, dstEid, std::move(payload),
                                              std::move(pvtData).value(), io);
    message->timer.expires_after(std::chrono::milliseconds(timeout));
    message->timer.async_wait(yield[ec]);
    if (ec && ec != boost::asio::error::operation_aborted)
    {
        transmissionQueue.dispose(dstEid, message);
        phosphor::logging::log<phosphor::logging::level::ERR>("Timer failed");
        return std::make_pair(
            std::make_error_code(std::errc::connection_aborted),
            std::vector<uint8_t>{});
    }
    if (!message->response)
    {
        transmissionQueue.dispose(dstEid, message);
        phosphor::logging::log<phosphor::logging::level::ERR>("No response");
        return std::make_pair(std::make_error_code(std::errc::timed_out),
                              std::vector<uint8_t>{});
    }
    if (message->response->empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>("Empty response");
        return std::make_pair(
            std::make_error_code(std::errc::no_message_available),
            std::vector<uint8_t>{});
    }

    return std::make_pair(std::error_code(),
                          std::move(message->response).value());
}

int MctpBinding::sendMctpMessagePayload(uint8_t dstEid, uint8_t msgTag,
                                        bool tagOwner,
                                        std::vector<uint8_t> payload)
{
    uint8_t msgType = payload[0]; // Always the first byte
    if (payload.size() > 0)
    {

        if (msgType == MCTP_MESSAGE_TYPE_MCTP_CTRL)
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Transmiting control messages");
        }
    }

    if (rsvBWActive && dstEid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (("SendMctpMessagePayload is not allowed. "
              "ReserveBandwidth is active "
              "for EID: ") +
             std::to_string(reservedEID))
                .c_str());
        return static_cast<int>(mctpErrorRsvBWIsNotActive);
    }
    std::optional<std::vector<uint8_t>> pvtData = getBindingPrivateData(dstEid);
    if (!pvtData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SendMctpMessagePayload: Invalid destination EID");
        return static_cast<int>(mctpInternalError);
    }

    std::vector<uint8_t> encryptedPayload;
    uint32_t deviceId = createDeviceId(dstEid, networkId);
    auto useDbus = checkSession(deviceId);

    if (secureTelemetryEnable && useDbus &&
        msgType != MCTP_MESSAGE_TYPE_MCTP_CTRL &&
        msgType != MCTP_MESSAGE_TYPE_SECUREDMSG &&
        msgType != MCTP_MESSAGE_TYPE_SPDM)
    {
        encryptPayloadUsingDBus(networkId, dstEid, payload, encryptedPayload);
        if (encryptedPayload.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Encryption failed");
            return static_cast<int>(mctpInternalError);
        }
        else
        {
            payload =
                std::move(encryptedPayload); // Use encrypted payload only if
                                             // encryption was successful
        }
    }

    if (mctp_message_tx(mctp, dstEid, payload.data(), payload.size(), tagOwner,
                        msgTag, pvtData->data()) < 0)
    {
        return static_cast<int>(mctpInternalError);
    }
    return static_cast<int>(mctpSuccess);
}
