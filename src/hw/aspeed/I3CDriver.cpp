#include "hw/aspeed/I3CDriver.hpp"

#include "utils/i3c_utils.hpp"

#include <iostream>

namespace hw
{
namespace aspeed
{

I3CDriver::I3CDriver(boost::asio::io_context& ioc, uint8_t busNum,
                     std::optional<uint8_t> pidMask) :
    streamMonitor(ioc)
{
    std::string i3cDeviceFile;
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
    phosphor::logging::log<phosphor::logging::level::ERR>("Start polling I3C file");
    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error reading I3C response");
                return;
            }
            phosphor::logging::log<phosphor::logging::level::ERR>("Polling wait returned for I3C file");
            int status = mctp_asti3c_rx(i3c, streamMonitorFd);
            if (status != 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("Error reading mctp_asti3c_rx " + std::to_string(status)).c_str());
            }
            pollRx();
        });
}

I3CDriver::~I3CDriver()
{
    phosphor::logging::log<phosphor::logging::level::ERR>("Freeing streamMonitor");
    streamMonitor.release();

    phosphor::logging::log<phosphor::logging::level::ERR>("Freeing mctp_asti3c");
    if (i3c)
    {
        mctp_asti3c_free(i3c);
    }
    phosphor::logging::log<phosphor::logging::level::ERR>("I3C driver destructor complete");
}

} // namespace aspeed
} // namespace hw