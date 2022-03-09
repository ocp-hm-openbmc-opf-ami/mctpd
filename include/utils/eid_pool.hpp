/*
// Copyright (c) 2021 Intel Corporation
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

#include <set>
#include <vector>

namespace mctpd
{
class EidPool
{
  public:
    void initializeEidPool(const std::set<mctp_eid_t>& pool);
    void updateEidStatus(const mctp_eid_t endpointId, const bool assigned);
    mctp_eid_t getAvailableEidFromPool();
    int getCountOfAvailableEidFromPool(const mctp_eid_t startingEID);

  private:
    std::vector<std::pair<mctp_eid_t, bool>> eidPool;
};
} // namespace mctpd