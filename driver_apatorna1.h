#pragma once

#include "driver.h"
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <algorithm>

namespace esphome {
namespace wmbus {

// Forward declaration of the decrypt_TPL_AES_CBC_IV function from utils.h
bool decrypt_TPL_AES_CBC_IV(std::vector<unsigned char> &frame, std::vector<unsigned char> &aeskey);

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
    ESP_LOGD(TAG, "ApatorNa1: trying to extract water consumption from telegram");
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
    // The CI field is at index 10 in the full telegram
    constexpr size_t CI_IDX = 10;
    
    // Check if telegram is long enough to contain CI field
    if (CI_IDX >= telegram.size()) {
      ESP_LOGD(TAG, "ApatorNa1: telegram too short to contain CI field");
      return {};
    }
    
    // Check if we have manufacturer-specific data (CI field = 0xA0 or 0xA1)
    if (telegram[CI_IDX] != 0xA0 && telegram[CI_IDX] != 0xA1) {
      ESP_LOGD(TAG, "ApatorNa1: CI field 0x%02X is not 0xA0/0xA1 (manufacturer specific)", telegram[CI_IDX]);
      return {};
    }
    
    // Create a copy of the telegram that we can modify for decryption
    std::vector<unsigned char> telegram_copy = telegram;
    
    // Create all-zeros AES key (as used in original wmbusmeters implementation)
    std::vector<unsigned char> aes_key(16, 0);
    
    // Use the built-in decrypt_TPL_AES_CBC_IV function to decrypt the telegram
    // This modifies the telegram_copy vector in-place
    if (!decrypt_TPL_AES_CBC_IV(telegram_copy, aes_key)) {
      ESP_LOGD(TAG, "ApatorNa1: decryption failed");
      return {};
    }
    
    // After decryption, we need to find the start of the decrypted data
    // In the original implementation, this starts at offset 15 for CI field 0xA0
    constexpr size_t DATA_OFFSET = 15;
    
    // Check if we have enough data after decryption
    if (telegram_copy.size() < DATA_OFFSET + 5) {
      ESP_LOGD(TAG, "ApatorNa1: decrypted telegram too short");
      return {};
    }
    
    // The multiplier is calculated from bits 4-5 of byte 1 in the decrypted data
    const int multiplier = std::pow(10, (telegram_copy[DATA_OFFSET + 1] & 0b00110000) >> 4);
    
    // The reading uses bytes 1-4 of the decrypted data
    const uint32_t reading = static_cast<uint32_t>(telegram_copy[DATA_OFFSET + 4]) << 20 |
                             static_cast<uint32_t>(telegram_copy[DATA_OFFSET + 3]) << 12 |
                             static_cast<uint32_t>(telegram_copy[DATA_OFFSET + 2]) << 4  |
                             (static_cast<uint32_t>(telegram_copy[DATA_OFFSET + 1]) & 0x0F);
    
    // Convert to cubic meters
    const double volume = static_cast<double>(reading) * multiplier / 1000.0;
    
    ESP_LOGD(TAG, "ApatorNa1: multiplier=%d, reading=%u, volume=%.3f m³", 
             multiplier, reading, volume);
    
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
