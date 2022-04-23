#pragma once

#include <libmctp.h>

#include <vector>

namespace hw
{

struct I3CEidInfo
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

    virtual bool setEndpointMap(std::vector<I3CEidInfo>& endpoints) = 0;

    virtual ~I3CDriver();
};

} // namespace hw
