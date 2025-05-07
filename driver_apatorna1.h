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
     ESP_LOGD(TAG, "ApatorNa1: trying get water from telegram");
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
   * Handles cases where the first DIF indicates consumption or is a selector to skip.
   */
  esphome::optional<double> get_total_water_m3(
      const std::vector<unsigned char> &telegram) {
    constexpr size_t CI_IDX = 10;
    size_t pos = CI_IDX + 1;
    if (pos >= telegram.size()) return {};

    auto parse_record = [&](size_t &p, unsigned char &dif_out, size_t &len_out) {
      unsigned char dif = telegram[p];
      size_t data_len = (dif & 0x07) <= 4 ? (dif & 0x07) : ((dif & 0x07) == 0x07 ? 4 : 0);
      dif_out = dif;
      len_out = data_len;
    };

    unsigned char dif;
    size_t len;
    // Try first record
    parse_record(pos, dif, len);
    if (len != 4) {
      // skip if valid selector
      if (len == 0) {
        // skip selector record header only
        pos += 1;
      } else {
        // skip selector + data
        pos += 1 + len;
      }
      if (pos >= telegram.size()) return {};
      // parse next record
      parse_record(pos, dif, len);
    }
    if (len != 4) {
      ESP_LOGD(TAG, "ApatorNa1: unexpected record length %u at pos %u", len, pos);
      return {};
    }

    // Exponent (3-bit two's complement in bits 4-6 of DIF)
    int exp_raw = (dif & 0x70) >> 4;
    int exp = (exp_raw & 0x04) ? exp_raw - 8 : exp_raw;
    double multiplier = std::pow(10.0, exp);

    // Read 4-byte value: low nibble of DIF + next 3 bytes
    if (pos + 4 >= telegram.size()) return {};
    uint32_t reading = (static_cast<uint32_t>(telegram[pos + 4]) << 20) |
                       (static_cast<uint32_t>(telegram[pos + 3]) << 12) |
                       (static_cast<uint32_t>(telegram[pos + 2]) << 4)  |
                       static_cast<uint32_t>(dif & 0x0F);
    double volume = static_cast<double>(reading) * multiplier / 1000.0;
    ESP_LOGD(TAG, "ApatorNa1 debug: pos=%u, dif=0x%02X, len=%u, exp=%d, reading=%u, volume=%.3f m³", pos, dif, len, exp, reading, volume);
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
