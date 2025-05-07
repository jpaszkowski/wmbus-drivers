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
   * @param telegram Full decrypted M-Bus frame
   * @return Map of sensor names to values, or empty optional if parsing fails
   */
  virtual esphome::optional<std::map<std::string, double>> get_values(
      std::vector<unsigned char> &telegram) override {
    // Parse total water consumption
    auto total = this->get_total_water_m3(telegram);
    if (total.has_value()) {
      ESP_LOGD(TAG, "ApatorNa1: total_water_m3 = %.3f m³", total.value());
      std::map<std::string, double> ret;
      ret["total_water_m3"] = total.value();
      return ret;
    }
    return {};
  }

private:
  /**
   * Parses the total water consumption (in m³) from the full frame
   */
  esphome::optional<double> get_total_water_m3(
      std::vector<unsigned char> &telegram) {
    // Ensure we have at least 15 bytes (header + first data)
    if (telegram.size() < 15) {
      return {};
    }
    // In short TPL frames, data starts after CI (index 10) + tpl-acc (index 11)
    // So payload begins at index 12
    size_t idx = 12;
    if (telegram.size() < idx + 4) {
      return {};
    }
    // Exponent is in bits 4-5 of payload byte 0 (telegram[idx])
    int exp = (telegram[idx] & 0x30) >> 4;
    int multiplier = static_cast<int>(std::pow(10, exp));
    // Reading is 4 bytes spanning nibbles: payload[0] low nibble and payload[1..3]
    uint32_t reading = ((static_cast<uint32_t>(telegram[idx + 3]) << 20) |
                        (static_cast<uint32_t>(telegram[idx + 2]) << 12) |
                        (static_cast<uint32_t>(telegram[idx + 1]) << 4)  |
                        (static_cast<uint32_t>(telegram[idx]) & 0x0F));
    double volume = static_cast<double>(reading) * multiplier / 1000.0;
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
