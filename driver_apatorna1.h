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
    : Driver("apatorna1", key) {
      ESP_LOGI(TAG, "ApatorNa1 driver created with key='%s'", key.c_str());
    }

  /**
   * Extracts available values from a decrypted telegram
   * @param telegram Full decrypted M-Bus frame
   * @return Map of sensor names to values, or empty optional if parsing fails
   */
  virtual esphome::optional<std::map<std::string, double>> get_values(
      std::vector<unsigned char> &telegram) override {
    ESP_LOGI(TAG, "ApatorNa1: trying get water from telegram");
    auto total = this->get_total_water_m3(telegram);
    if (total.has_value()) {
      // Check if the value is reasonable (for a water meter)
      if (total.value() > 1000.0) {
        ESP_LOGW(TAG, "ApatorNa1: Suspicious water value: %.3f m³ - likely decoding error", total.value());
        return {}; // Don't return unreasonable values
      }
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
      ESP_LOGI(TAG, "ApatorNa1: telegram too short to contain CI field");
      return {};
    }
    
    // Print the full telegram for debugging
    std::string hex;
    for (const auto& byte : telegram) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02X", byte);
      hex += buf;
    }
    ESP_LOGI(TAG, "ApatorNa1: Raw telegram: %s", hex.c_str());
    
    // Check if we have manufacturer-specific data (CI field = 0xA0 or 0xA1)
    if (telegram[CI_IDX] != 0xA0 && telegram[CI_IDX] != 0xA1) {
      ESP_LOGI(TAG, "ApatorNa1: CI field 0x%02X is not 0xA0/0xA1 (manufacturer specific)", telegram[CI_IDX]);
      return {};
    }
    
    ESP_LOGI(TAG, "ApatorNa1: CI field is 0x%02X - telegram is valid format", telegram[CI_IDX]);

    // Extract payload from telegram (everything after CI field)
    std::vector<unsigned char> payload;
    for (size_t i = CI_IDX + 1; i < telegram.size(); i++) {
      payload.push_back(telegram[i]);
    }
    
    // Print payload for debugging
    std::string payload_hex;
    for (const auto& byte : payload) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02X", byte);
      payload_hex += buf;
    }
    ESP_LOGI(TAG, "ApatorNa1: Payload: %s", payload_hex.c_str());
    
    // Check if payload is large enough
    if (payload.size() < 4) {
      ESP_LOGI(TAG, "ApatorNa1: Payload too small");
      return {};
    }
     // Create frame from payload bytes 2-18 for decryption
    std::vector<unsigned char> frame;
    for (size_t i = 2; i < std::min(payload.size(), static_cast<size_t>(18)); i++) {
      frame.push_back(payload[i]);
    }
    
    // Print frame for debugging
    std::string frame_hex;
    for (const auto& byte : frame) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02X", byte);
      frame_hex += buf;
    }
    ESP_LOGI(TAG, "ApatorNa1: Frame before decryption: %s", frame_hex.c_str());
    
    // Create all-zeros AES key (as used in original wmbusmeters implementation)
    std::vector<unsigned char> aes_key(16, 0);
    
    // Create a copy of the telegram that we can modify for decryption
    std::vector<unsigned char> telegram_copy = telegram;
    
    // Use the built-in decrypt_TPL_AES_CBC_IV function to decrypt the telegram
    // This modifies the telegram_copy vector in-place
    if (!decrypt_TPL_AES_CBC_IV(telegram_copy, aes_key)) {
      ESP_LOGI(TAG, "ApatorNa1: decryption failed with all-zeros key");
      return {};
    }
    
    // Print the decrypted telegram for debugging
    std::string decrypted_hex;
    for (const auto& byte : telegram_copy) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02X", byte);
      decrypted_hex += buf;
    }
    ESP_LOGI(TAG, "ApatorNa1: Decrypted telegram: %s", decrypted_hex.c_str());
    
    // Skip to the beginning of decrypted data (offset is 0 after decrypt_TPL_AES_CBC_IV)
    size_t offset = CI_IDX + 1; // Start right after CI field
    
    // Check if we have enough data
    if (telegram_copy.size() < offset + 5) {
      ESP_LOGI(TAG, "ApatorNa1: decrypted telegram too short");
      return {};
    }
    
    // Now we'll extract data from the decrypted frame
    // After decrypt_TPL_AES_CBC_IV, we need to check at offset 0
    // but for safety, let's check if there's a 2F2F pattern anywhere
    bool found_2f2f = false;
    size_t data_offset = 0;
    
    for (size_t i = 0; i < telegram_copy.size() - 1; i++) {
      if (telegram_copy[i] == 0x2F && telegram_copy[i+1] == 0x2F) {
        found_2f2f = true;
        data_offset = i + 2; // Skip the 2F2F marker
        ESP_LOGI(TAG, "ApatorNa1: found 2F2F verification pattern at offset %d", i);
        break;
      }
    }
    
    // Check if we have enough data after 2F2F (if found)
    if (found_2f2f && telegram_copy.size() < data_offset + 5) {
      ESP_LOGI(TAG, "ApatorNa1: decrypted telegram too short after 2F2F marker");
      return {};
    }
    
    // Try to get data either after 2F2F marker or directly from telegram_copy
    // based on your original test code
    double volume = 0.0;
    uint32_t reading = 0;
    int multiplier = 1;
    
    if (found_2f2f) {
      // The multiplier is calculated from bits 4-5 of byte 1 in the decrypted data
      multiplier = std::pow(10, (telegram_copy[data_offset + 1] & 0b00110000) >> 4);
      
      // The reading uses bytes 1-4 of the decrypted data
      reading = static_cast<uint32_t>(telegram_copy[data_offset + 4]) << 20 |
                static_cast<uint32_t>(telegram_copy[data_offset + 3]) << 12 |
                static_cast<uint32_t>(telegram_copy[data_offset + 2]) << 4  |
                (static_cast<uint32_t>(telegram_copy[data_offset + 1]) & 0x0F);
      
      // Convert to cubic meters
      volume = static_cast<double>(reading) * multiplier / 1000.0;
      
      ESP_LOGI(TAG, "ApatorNa1: DATA_OFFSET=%d, multiplier=%d, reading=%u, volume=%.3f m³",
              data_offset, multiplier, reading, volume);
    } else {
      // If 2F2F pattern wasn't found, try to use the first part of decrypted data
      // The multiplier is calculated from bits 4-5 of byte 1 in the decrypted data
      multiplier = std::pow(10, (telegram_copy[offset + 1] & 0b00110000) >> 4);
      
      // The reading uses bytes 1-4 of the decrypted data
      reading = static_cast<uint32_t>(telegram_copy[offset + 4]) << 20 |
                static_cast<uint32_t>(telegram_copy[offset + 3]) << 12 |
                static_cast<uint32_t>(telegram_copy[offset + 2]) << 4  |
                (static_cast<uint32_t>(telegram_copy[offset + 1]) & 0x0F);
      
      // Convert to cubic meters
      volume = static_cast<double>(reading) * multiplier / 1000.0;
      
      ESP_LOGI(TAG, "ApatorNa1: DATA_OFFSET=%d, multiplier=%d, reading=%u, volume=%.3f m³",
              offset, multiplier, reading, volume);
    }
    
    return volume;
    
    return volume;
    
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
