#include <optional>
#include <phosphor-logging/log.hpp>
#include <string>
#include <vector>

std::vector<std::string> getDevFilePaths(std::string& matchString);

bool findMCTPI3CDevice(uint8_t busNum, std::optional<uint8_t> pidMask,
                       std::string& file);

bool getPID(std::string& path, std::string& pidStr);
bool getAddr(std::string& path, uint8_t& addr);