#pragma once

#include "driver.h"
#include <vector>
#include <map>
#include <string>
#include <cmath>

namespace esphome {
namespace wmbus {

/**
 * ApatorNa1 water meter driver
 * Parses decrypted telegram to extract total water consumption (m³)
 */
struct ApatorNa1 : public Driver {
  /**
   * @param key AES key as hex string (optional)
   */
  ApatorNa1(const std::string &key = "")
    : Driver("apatorna1", key) {}

  /**
   * Extracts available values from a decrypted telegram
   * @param telegram Vector of bytes containing decrypted telegram data
   * @return Map of sensor names to values, or empty optional if parsing fails
   */
  virtual esphome::optional<std::map<std::string, double>> get_values(
      std::vector<unsigned char> &telegram) override {
    std::map<std::string, double> ret;
    add_to_map(ret, "total_water_m3", this->get_total_water_m3(telegram));
    if (!ret.empty()) {
      return ret;
    }
    return {};
  }

private:
  /**
   * Parses the total water consumption (in m³) from the telegram
   */
  esphome::optional<double> get_total_water_m3(
      std::vector<unsigned char> &telegram) {
    // Need at least 5 bytes for exponent and reading
    if (telegram.size() < 5) {
      return {};
    }
    // Exponent is in bits 4-5 of byte 1
    int exp = (telegram[1] & 0x30) >> 4;
    int multiplier = static_cast<int>(std::pow(10, exp));
    // Reading is 4 bytes spanning nibbles
    uint32_t reading = (static_cast<uint32_t>(telegram[4]) << 20) |
                       (static_cast<uint32_t>(telegram[3]) << 12) |
                       (static_cast<uint32_t>(telegram[2]) << 4)  |
                       (static_cast<uint32_t>(telegram[1]) & 0x0F);
    double volume = static_cast<double>(reading) * multiplier / 1000.0;
    ESP_LOGVV(TAG, "Parsed total_water_m3: reading=%u, multiplier=%d, volume=%f", reading, multiplier, volume);
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
