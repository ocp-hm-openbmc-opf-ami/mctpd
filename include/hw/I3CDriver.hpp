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
    virtual uint8_t getOwnAddress() = 0;
    virtual uint8_t getDeviceAddress() = 0;
    virtual bool isControllerRole() = 0;
    virtual void rescanBus() = 0;
    virtual bool getTargetStatus(uint32_t&) = 0;

    virtual ~I3CDriver() = default;
};

} // namespace hw
