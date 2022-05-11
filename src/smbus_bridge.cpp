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

#include "smbus_bridge.hpp"

#include "utils/smbus_utils.hpp"
#include "utils/utils.hpp"

#include <fstream>
#include <phosphor-logging/log.hpp>

#include "libmctp-smbus.h"

extern "C" {
#include <errno.h>
#include <i2c/smbus.h>
#include <linux/i2c-dev.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
}

std::map<MuxIdleModes, std::string> muxIdleModesMap{
    {MuxIdleModes::muxIdleModeConnect, "-1"},
    {MuxIdleModes::muxIdleModeDisconnect, "-2"},
};

SMBusBridge::SMBusBridge(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<object_server>& objServer, const std::string& objPath,
    const SMBusConfiguration& conf, boost::asio::io_context& ioc,
    std::shared_ptr<boost::asio::posix::stream_descriptor>&& i2cMuxMonitor) :
    SMBusEndpoint(conn, objServer, objPath, conf, ioc),
    addRootDevices(true), reserveBWTimer(ioc), refreshMuxTimer(ioc),
    scanTimer(ioc), muxMonitor{std::move(i2cMuxMonitor)}

{
}

SMBusBridge::~SMBusBridge()
{
    restoreMuxIdleMode();
}

void SMBusBridge::scanPort(const int scanFd,
                           std::set<std::pair<int, uint8_t>>& deviceMap)
{
    if (scanFd < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid I2C port fd");
        return;
    }

    for (uint8_t it : supportedEndpointSlaveAddress)
    {
        if (ioctl(scanFd, I2C_SLAVE, it) < 0)
        {
            // busy slave
            continue;
        }

        else
        {
            if ((it >= 0x30 && it <= 0x37) || (it >= 0x50 && it <= 0x5F))
            {
                // EEPROM address range. Use read to detect
                if (i2c_smbus_read_byte(scanFd) < 0)
                {
                    continue;
                }
            }
            else
            {
                if (i2c_smbus_write_quick(scanFd, I2C_SMBUS_WRITE) < 0)
                {
                    continue;
                }
            }
        }

        /* If we are scanning a mux fd, we will encounter root bus
         * i2c devices, which needs to be part of root bus's devicemap.
         * Skip adding them to the muxfd related devicemap */

        if (scanFd != outFd &&
            rootDeviceMap.count(std::make_pair(outFd, it)) != 0)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Skipping device " + std::to_string(it)).c_str());
            continue;
        }

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Adding device " + std::to_string(it)).c_str());

        deviceMap.insert(std::make_pair(scanFd, it));
    }
}

std::map<int, int> SMBusBridge::getMuxFds(const std::string& rootPort)
{
    auto devDir = fs::path("/dev/");
    auto matchString = std::string(R"(i2c-\d+$)");
    std::vector<std::string> i2cBuses{};

    // Search for mux ports
    if (!findFiles(devDir, matchString, i2cBuses))
    {
        throwRunTimeError("unable to find i2c devices");
    }

    std::map<int, int> muxes;
    for (const auto& i2cPath : i2cBuses)
    {
        std::string i2cPort;
        std::string rootBus;
        if (!getBusNumFromPath(i2cPath, i2cPort))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "i2c bus path is malformed",
                phosphor::logging::entry("PATH=%s", i2cPath.c_str()));
            continue;
        }

        if (!isMuxBus(i2cPort))
        {
            continue; // we found regular i2c port
        }

        if (!getRootBus(i2cPort, rootBus))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error getting root port for the bus",
                phosphor::logging::entry("BUS:", i2cPort.c_str()));
            continue;
        }

        // Add to list of muxes if rootport matches to the one defined in mctp
        // configuration
        if (rootPort == rootBus)
        {
            int muxfd = open(i2cPath.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
            if (muxfd < 0)
            {
                continue;
            }
            muxes.emplace(muxfd, std::stoi(i2cPort));
        }
    }
    return muxes;
}

bool SMBusBridge::reserveBandwidth(const mctp_eid_t eid, const uint16_t timeout)
{
    if (rsvBWActive && eid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (("reserveBandwidth is not allowed for EID: " +
              std::to_string(eid) + ". It is active for EID: ") +
             std::to_string(reservedEID))
                .c_str());
        return false;
    }
    std::optional<std::vector<uint8_t>> pvtData = getBindingPrivateData(eid);
    if (!pvtData)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "reserveBandwidth failed. Invalid destination EID");
        return false;
    }
    const mctp_smbus_pkt_private* prvt =
        reinterpret_cast<const mctp_smbus_pkt_private*>(pvtData->data());
    if (prvt->mux_flags != IS_MUX_PORT)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "reserveBandwidth not required, fd is not a mux port");
        return false;
    }

    if (!rsvBWActive)
    {
        if (mctp_smbus_init_pull_model(prvt) < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "reserveBandwidth: init pull model failed");
            return false;
        }
        // TODO: Set only the required MUX.
        setMuxIdleMode(MuxIdleModes::muxIdleModeConnect);
        rsvBWActive = true;
        reservedEID = eid;
    }

    startTimerAndReleaseBW(timeout, *prvt);
    return true;
}

bool SMBusBridge::releaseBandwidth(const mctp_eid_t eid)
{
    if (!rsvBWActive || eid != reservedEID)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (("reserveBandwidth is not active for EID: ") + std::to_string(eid))
                .c_str());
        return false;
    }
    reserveBWTimer.cancel();
    return true;
}

void SMBusBridge::startTimerAndReleaseBW(const uint16_t interval,
                                         const mctp_smbus_pkt_private prvt)
{
    // expires_after() return the number of asynchronous operations that were
    // cancelled.
    ret = reserveBWTimer.expires_after(
        std::chrono::milliseconds(interval * 1000));
    reserveBWTimer.async_wait([this,
                               prvt](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted)
        {
            // timer aborted do nothing
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "startTimerAndReleaseBW: timer operation_aborted");
        }
        else if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "startTimerAndReleaseBW: reserveBWTimer failed");
        }
        if (ret)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "startTimerAndReleaseBW: timer restarted");
            ret = 0;
            return;
        }
        setMuxIdleMode(MuxIdleModes::muxIdleModeDisconnect);
        if (mctp_smbus_exit_pull_model(&prvt) < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "startTimerAndReleaseBW: mctp_smbus_exit_pull_model failed");
            return;
        }
        rsvBWActive = false;
        reservedEID = 0;
    });
}

void SMBusBridge::triggerDeviceDiscovery()
{
    scanTimer.cancel();
}

void SMBusBridge::scanDevices()
{
    phosphor::logging::log<phosphor::logging::level::DEBUG>("Scanning devices");

    boost::asio::spawn(io, [this](boost::asio::yield_context yield) {
        if (!rsvBWActive)
        {
            deviceWatcher.deviceDiscoveryInit();
            initEndpointDiscovery(yield);
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Reserve bandwidth active. Unable to scan devices");
        }

        scanTimer.expires_after(std::chrono::seconds(scanInterval));
        scanTimer.async_wait([this](const boost::system::error_code& ec) {
            if (ec && ec != boost::asio::error::operation_aborted)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Device scanning timer failed");
                return;
            }
            if (ec == boost::asio::error::operation_aborted)
            {
                phosphor::logging::log<phosphor::logging::level::WARNING>(
                    "Device scan wait timer aborted. Re-triggering device "
                    "discovery");
            }
            scanDevices();
        });
    });
}

void SMBusBridge::restoreMuxIdleMode()
{
    auto logMuxErr = [](const std::string& path) {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Unable to restore mux idle mode",
            phosphor::logging::entry("MUX_PATH=%s", path.c_str()));
    };

    for (const auto& [path, idleMode] : muxIdleModeMap)
    {
        fs::path idlePath = fs::path(path);
        if (!fs::exists(idlePath))
        {
            logMuxErr(path);
            continue;
        }

        std::fstream idleFile(idlePath);
        if (idleFile.good())
        {
            idleFile << idleMode;
            if (idleFile.bad())
            {
                logMuxErr(path);
            }
        }
        else
        {
            logMuxErr(path);
        }
    }
}

void SMBusBridge::setMuxIdleMode(const MuxIdleModes mode)
{
    auto itr = muxIdleModesMap.find(mode);
    if (itr == muxIdleModesMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Inavlid mux idle mode");
        return;
    }
    std::string rootPort;
    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in finding root port");
    }

    fs::path rootPath = fs::path("/sys/bus/i2c/devices/i2c-" + rootPort + "/");
    std::string matchString = rootPort + std::string(R"(-\d+$)");
    std::vector<std::string> i2cMuxes{};
    static bool muxIdleModeFlag = false;

    // Search for mux ports
    if (!findFiles(rootPath, matchString, i2cMuxes))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No mux interfaces found");
        return;
    }

    for (const auto& muxPath : i2cMuxes)
    {
        std::string path = muxPath + "/idle_state";
        fs::path idlePath = fs::path(path);
        if (!fs::exists(idlePath))
        {
            continue;
        }

        std::fstream idleFile(idlePath);
        if (idleFile.good())
        {
            if (!muxIdleModeFlag)
            {
                std::string currentMuxIdleMode;
                idleFile >> currentMuxIdleMode;
                muxIdleModeMap.insert_or_assign(path, currentMuxIdleMode);

                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    (path + " " + currentMuxIdleMode).c_str());
            }

            idleFile << itr->second;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to set idle mode for mux",
                phosphor::logging::entry("MUX_PATH=%s", idlePath.c_str()));
        }
    }
    muxIdleModeFlag = true;
}

inline void SMBusBridge::handleMuxInotifyEvent(const std::string& name)
{
    if (boost::starts_with(name, "i2c-"))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Detected change on bus " + name).c_str());

        // Delay 1s to refresh only once as multiple i2c
        // buses will change when handling mux
        refreshMuxTimer.expires_after(std::chrono::seconds(1));
        refreshMuxTimer.async_wait(
            [this](const boost::system::error_code& ec2) {
                // Calling expires_after will invoke this handler with
                // operation_aborted, just ignore it as we only need to
                // rescan mux on last inotify event
                if (ec2 == boost::asio::error::operation_aborted)
                {
                    return;
                }

                std::string rootPort;
                if (!getBusNumFromPath(bus, rootPort))
                {
                    throwRunTimeError("Error in finding root port");
                }

                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "i2c bus change detected, refreshing "
                    "muxPortMap");
                muxPortMap = getMuxFds(rootPort);
                scanTimer.cancel();
            });
    }
}

void SMBusBridge::monitorMuxChange()
{
    static std::array<char, 4096> readBuffer;

    muxMonitor->async_read_some(
        boost::asio::buffer(readBuffer),
        [&](const boost::system::error_code& ec, std::size_t bytesTransferred) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("monitorMuxChange: Callback Error " + ec.message())
                        .c_str());
                return;
            }
            size_t index = 0;
            while ((index + sizeof(inotify_event)) <= bytesTransferred)
            {
                // Using reinterpret_cast gives a cast-align error here
                inotify_event event;
                const char* eventPtr = &readBuffer[index];
                memcpy(&event, eventPtr, sizeof(inotify_event));
                switch (event.mask)
                {
                    case IN_CREATE:
                    case IN_MOVED_TO:
                    case IN_DELETE:
                        std::string name(eventPtr + sizeof(inotify_event));
                        handleMuxInotifyEvent(name);
                }
                index += sizeof(inotify_event) + event.len;
            }
            monitorMuxChange();
        });
}

void SMBusBridge::setupMuxMonitor()
{
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0)
    {
        throwRunTimeError("inotify_init failed");
    }
    int watch =
        inotify_add_watch(fd, "/dev", IN_CREATE | IN_MOVED_TO | IN_DELETE);
    if (watch < 0)
    {
        throwRunTimeError("inotify_add_watch failed");
    }
    muxMonitor->assign(fd);
    monitorMuxChange();
}

void SMBusBridge::scanMuxBus(std::set<std::pair<int, uint8_t>>& deviceMap)
{
    for (const auto& [muxFd, muxPort] : muxPortMap)
    {
        // Scan each port only once
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Scanning Mux " + std::to_string(muxPort)).c_str());
        scanPort(muxFd, deviceMap);
    }
}

void SMBusBridge::initEndpointDiscovery(boost::asio::yield_context& yield)
{
    std::set<std::pair<int, uint8_t>> registerDeviceMap;

    if (addRootDevices)
    {
        addRootDevices = false;
        for (const auto& device : rootDeviceMap)
        {
            registerDeviceMap.insert(device);
        }
    }

    // Scan mux bus to get the list of fd and the corresponding slave address of
    // all the mux ports
    scanMuxBus(registerDeviceMap);

    /* Since i2c muxes restrict that only one command needs to be
     * in flight, we cannot register multiple endpoints in parallel.
     * Thus, in a single yield_context, all the discovered devices
     * are attempted with registration sequentially */
    for (const auto& device : registerDeviceMap)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("Device discovery: Checking device " +
             std::to_string(std::get<1>(device)))
                .c_str());

        struct mctp_smbus_pkt_private smbusBindingPvt;
        smbusBindingPvt.fd = std::get<0>(device);

        if (muxPortMap.count(smbusBindingPvt.fd) != 0)
        {
            smbusBindingPvt.mux_hold_timeout = ctrlTxRetryDelay;
            smbusBindingPvt.mux_flags = 0x80;
        }
        else
        {
            smbusBindingPvt.mux_hold_timeout = 0;
            smbusBindingPvt.mux_flags = 0;
        }
        /* Set 8 bit i2c slave address */
        smbusBindingPvt.slave_addr =
            static_cast<uint8_t>((std::get<1>(device) << 1));

        auto const ptr = reinterpret_cast<uint8_t*>(&smbusBindingPvt);
        std::vector<uint8_t> bindingPvtVect(ptr, ptr + sizeof(smbusBindingPvt));
        if (!deviceWatcher.isDeviceGoodForInit(bindingPvtVect))
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Device found in ignore list. Skipping discovery");
            continue;
        }

        mctp_eid_t registeredEid = getEIDFromDeviceTable(bindingPvtVect);
        std::optional<mctp_eid_t> eid =
            registerEndpoint(yield, bindingPvtVect, registeredEid);

        if (eid.has_value() && eid.value() != MCTP_EID_NULL)
        {
            DeviceTableEntry_t entry =
                std::make_pair(eid.value(), smbusBindingPvt);
            bool newEntry = !isDeviceEntryPresent(entry, smbusDeviceTable);
            bool noDeviceUpdate = !newEntry && eid.value() == registeredEid;
            bool deviceUpdated = !newEntry && eid.value() != registeredEid;

            auto logDeviceDetails = [&]() {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    ("SMBus device at bus:" +
                     std::to_string(getBusNumByFd(smbusBindingPvt.fd)) +
                     ", 8 bit address: " +
                     std::to_string(smbusBindingPvt.slave_addr) +
                     " registered at EID " + std::to_string(eid.value()))
                        .c_str());
            };

            if (noDeviceUpdate)
            {
                continue;
            }
            else if (newEntry)
            {
                smbusDeviceTable.push_back(entry);
                logDeviceDetails();
            }
            else if (deviceUpdated)
            {
                unregisterEndpoint(registeredEid);
                removeDeviceTableEntry(registeredEid);
                smbusDeviceTable.push_back(entry);
                logDeviceDetails();
            }
        }
    }

    if (registerDeviceMap.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No device found");
        for (auto& deviceTableEntry : smbusDeviceTable)
        {
            unregisterEndpoint(std::get<0>(deviceTableEntry));
        }
        smbusDeviceTable.clear();
    }
}