#pragma once

#include "driver.h"
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <algorithm>

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
   * AES-CBC-IV decryption implementation
   * Based on wmbusmeters.org implementation
   */
  bool decrypt_AES_CBC_IV(const std::vector<unsigned char>& input,
                          std::vector<unsigned char>& output,
                          const std::vector<unsigned char>& key,
                          const std::vector<unsigned char>& telegram) {
    // We need mbedtls for AES on ESP32
    if (input.size() < 16) {
      ESP_LOGW(TAG, "Input too small for decryption");
      return false;
    }

    // Create IV using similar logic to wmbusmeters
    std::vector<unsigned char> iv(16, 0);
    
    // First 2 bytes: manufacturer (M-field)
    iv[0] = telegram[2]; // Manufacturer byte 1
    iv[1] = telegram[3]; // Manufacturer byte 2
    
    // Next 6 bytes: device ID (A-field)
    for (int i = 0; i < 6; ++i) {
      iv[i+2] = telegram[4+i]; // Device ID bytes
    }
    
    // Last 8 bytes: payload[0] repeated (ACC)
    unsigned char acc = telegram[11]; // First byte after CI field
    for (int i = 0; i < 8; ++i) {
      iv[i+8] = acc;
    }
    
    // Make sure input size is multiple of 16 (AES block size)
    size_t num_bytes_to_decrypt = (input.size() / 16) * 16;
    
    // Use mbedtls for AES decryption
    output = this->aes_decrypt(input, key, iv);
    
    return !output.empty();
  }

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
    
    // Check if we have manufacturer-specific data (CI field = 0xA0)
    if (telegram[CI_IDX] != 0xA0) {
      ESP_LOGD(TAG, "ApatorNa1: CI field 0x%02X is not 0xA0 (manufacturer specific)", telegram[CI_IDX]);
      return {};
    }
    
    // Extract payload from telegram
    std::vector<unsigned char> payload;
    for (size_t i = CI_IDX + 1; i < telegram.size(); i++) {
      payload.push_back(telegram[i]);
    }
    
    // Check if payload is large enough
    if (payload.size() < 4) {
      ESP_LOGD(TAG, "ApatorNa1: payload too small");
      return {};
    }
    
    // Create frame from payload bytes 2-18 (like in original implementation)
    std::vector<unsigned char> frame;
    for (size_t i = 2; i < std::min(payload.size(), static_cast<size_t>(18)); i++) {
      frame.push_back(payload[i]);
    }
    
    // Decrypt frame using AES-CBC-IV with key "00000000000000000000000000000000"
    std::vector<unsigned char> aes_key(16, 0);  // All zeros key
    std::vector<unsigned char> decrypted_frame;
    
    bool decryption_success = decrypt_AES_CBC_IV(frame, decrypted_frame, aes_key, telegram);
    
    if (!decryption_success) {
      ESP_LOGD(TAG, "ApatorNa1: decryption failed");
      return {};
    }
    
    // Calculate water consumption from decrypted frame
    if (decrypted_frame.size() < 5) {
      ESP_LOGD(TAG, "ApatorNa1: decrypted frame too short");
      return {};
    }
    
    // The multiplier is calculated from bits 4-5 of byte 1 in the frame
    const int multiplier = std::pow(10, (decrypted_frame[1] & 0b00110000) >> 4);
    
    // The reading uses bytes 1-4 of the frame
    const uint32_t reading = static_cast<uint32_t>(decrypted_frame[4]) << 20 |
                           static_cast<uint32_t>(decrypted_frame[3]) << 12 |
                           static_cast<uint32_t>(decrypted_frame[2]) << 4  |
                           (static_cast<uint32_t>(decrypted_frame[1]) & 0x0F);
    
    // Convert to cubic meters
    const double volume = static_cast<double>(reading) * multiplier / 1000.0;
    
    ESP_LOGD(TAG, "ApatorNa1: multiplier=%d, reading=%u, volume=%.3f m³", 
             multiplier, reading, volume);
    
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
