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

#include <vector>

namespace hw
{

struct EidInfo
{
    uint8_t eid;
    uint16_t bdf;
};

class PCIeDriver
{
  public:
    virtual void init() = 0;
    virtual mctp_binding* binding() = 0;
    virtual void pollRx() = 0;

    virtual bool registerAsDefault() = 0;
    virtual bool getBdf(uint16_t& bdf) = 0;
    virtual uint8_t getMediumId() = 0;
    virtual bool setEndpointMap(std::vector<EidInfo>& endpoints) = 0;

    virtual ~PCIeDriver();
};

namespace bdf
{
static inline uint8_t getBus(uint16_t bdf)
{
    return static_cast<uint8_t>((bdf >> 8) & 0xff);
}

static inline uint8_t getDevice(uint16_t bdf)
{
    return static_cast<uint8_t>((bdf >> 3) & 0x1f);
}

static inline uint8_t getFunction(uint16_t bdf)
{
    return static_cast<uint8_t>(bdf & 0x07);
}
} // namespace bdf

} // namespace hw
