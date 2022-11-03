#include "hw/aspeed/I3CDriver.hpp"

#include "utils/i3c_utils.hpp"

#include <string>

namespace hw
{
namespace aspeed
{

I3CDriver::I3CDriver(boost::asio::io_context& ioc, uint8_t busNum,
                     std::optional<uint8_t> pidMask) :
    streamMonitor(ioc)
{
    if (pidMask.has_value())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "BMC is a I3C Primary ");
        isController = true;
        cpuPidMask = pidMask.value();
    }

    if (findMCTPI3CDevice(busNum, pidMask, i3cDeviceFile))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("I3C device file: " + i3cDeviceFile).c_str());
        streamMonitorFd = open(i3cDeviceFile.c_str(), O_RDWR);
        streamMonitor.assign(streamMonitorFd);
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No device found");
    }
}

int I3CDriver::getDriverFd()
{
    return streamMonitorFd;
}

void I3CDriver::init()
{
    i3c = mctp_asti3c_init();
    if (i3c == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP I3C init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

mctp_binding* I3CDriver::binding()
{
    // If this API gets invoked before init(), i3c binding might not be
    // initialised
    if (i3c == nullptr)
    {
        return nullptr;
    }
    return &i3c->binding;
}

void I3CDriver::pollRx()
{
    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading I3C response");
                return;
            }
            if (mctp_asti3c_rx(i3c, streamMonitorFd))
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Error reading I3C response");
            }
            pollRx();
        });
}

I3CDriver::~I3CDriver()
{
    streamMonitor.release();

    if (i3c)
    {
        mctp_asti3c_free(i3c);
    }
}

uint8_t I3CDriver::getOwnAddress()
{
    // If BMC is I3C Primary, return 0
    uint8_t ownDAA = 0;

    // Else, go through sysfs file paths and determine BMC's device address
    if (!isController)
    {
        if (!getAddr(i3cDeviceFile, ownDAA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error reading own I3C Addr");
        }
    }

    return ownDAA;
}

uint8_t I3CDriver::getDeviceAddress()
{
    // If BMC is secondary, then the remote I3C device is an I3C Controller -
    // thus return 0
    uint8_t deviceDAA = 0;
    // If remote I3C device is a I3C secondary, then go through sysfs paths and
    // determine device's address from i3c-mctp-x
    if (isController)
    {
        if (!getAddr(i3cDeviceFile, deviceDAA))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error reading device I3C Addr");
        }
    }
    return deviceDAA;
}
} // namespace aspeed
} // namespace hw