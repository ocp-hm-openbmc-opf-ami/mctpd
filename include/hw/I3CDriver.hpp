#pragma once

#include <libmctp.h>

namespace hw
{

struct I3CEIDInfo
{
    uint8_t eid;
    uint8_t address;
};

class I3CDriver
{
  public:
    virtual void init() = 0;
    virtual void pollRx() = 0;
    virtual mctp_binding* binding() = 0;
    virtual int getDriverFd() = 0;

    virtual ~I3CDriver() = default;
};

} // namespace hw
