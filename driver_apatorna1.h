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
 * Parses decrypted M-Bus telegram to extract total water consumption (m³)
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
    auto total = this->get_total_water_m3(telegram);
    if (total.has_value()) {
      ESP_LOGI(TAG, "ApatorNa1: total_water_m3 = %.3f m³", total.value());
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
      const std::vector<unsigned char> &telegram) {
    // CI field at index 10, first DIF at 11
    constexpr size_t CI_IDX = 10;
    size_t pos = CI_IDX + 1;
    if (pos >= telegram.size()) return {};
    // First record: skip manufacturer selector or similar
    unsigned char dif1 = telegram[pos];
    // Length code: low nibble, 7 means 4 bytes per M-Bus spec
    size_t len1 = (dif1 & 0x07) <= 4 ? (dif1 & 0x07) : ((dif1 & 0x07) == 0x07 ? 4 : 0);
    if (len1 == 0) return {};
    pos += 1 + len1;
    if (pos >= telegram.size()) return {};
    // Second record: actual consumption data
    unsigned char dif = telegram[pos];
    size_t len = (dif & 0x07) <= 4 ? (dif & 0x07) : ((dif & 0x07) == 0x07 ? 4 : 0);
    if (len != 4) return {};
    // Exponent (3-bit two's complement in bits 4-6)
    int exp_raw = (dif & 0x70) >> 4;
    int exp = (exp_raw & 0x04) ? exp_raw - 8 : exp_raw;
    double multiplier = std::pow(10.0, exp);
    // Read 4-byte value: low nibble of DIF + next 3 bytes
    uint32_t reading = (static_cast<uint32_t>(telegram[pos + 4]) << 20) |
                       (static_cast<uint32_t>(telegram[pos + 3]) << 12) |
                       (static_cast<uint32_t>(telegram[pos + 2]) << 4)  |
                       static_cast<uint32_t>(dif & 0x0F);
    double volume = static_cast<double>(reading) * multiplier / 1000.0;
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
