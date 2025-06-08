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
    
    // Create all-zeros AES key (as used in original wmbusmeters implementation)
    std::vector<unsigned char> aes_key(16, 0);
    
    // Create a copy of the telegram that we can modify for decryption
    std::vector<unsigned char> telegram_copy = telegram;
    
    // Create frame from payload bytes 2-18 for decryption
    int pos = CI_IDX + 3; // Skip CI field and first 2 payload bytes
    
    if (pos + 1 >= telegram.size()) {
      ESP_LOGI(TAG, "ApatorNa1: unexpected record length %d at pos %d", 
               (int)telegram.size() - pos, pos);
      return {};
    }
    
    // Get data and check its length (DIF byte contains the data length)
    unsigned char dif = telegram[pos];
    int data_len = 0;
    int exp = 0;
    
    // Check if it's a variable length data field
    if ((dif & 0x0F) == 0x0D) {
      // Variable length, length is in the next byte
      data_len = telegram[pos+1];
      pos += 2; // Skip DIF and length byte
    } else {
      // Fixed length, determine from DIF
      switch (dif & 0x0F) {
        case 0x01: data_len = 1; break; // 8 bit integer
        case 0x02: data_len = 2; break; // 16 bit integer
        case 0x03: data_len = 3; break; // 24 bit integer
        case 0x04: data_len = 4; break; // 32 bit integer
        case 0x06: data_len = 6; break; // 48 bit integer
        case 0x07: data_len = 8; break; // 64 bit integer
        default:
          ESP_LOGI(TAG, "ApatorNa1: unsupported DIF 0x%02X", dif);
          return {};
      }
      pos += 1; // Skip DIF
    }
    
    // Check for exponent in DIF
    if (dif & 0x20) {
      exp = -1; // Divide by 10
    } else if (dif & 0x40) {
      exp = 1;  // Multiply by 10
    }
    
    // Check if we have enough data
    if (pos + data_len > telegram.size()) {
      ESP_LOGI(TAG, "ApatorNa1: not enough data (need %d bytes at pos %d)", 
               data_len, pos);
      return {};
    }
    
    // Read the value
    uint32_t reading = 0;
    for (int i = 0; i < data_len; i++) {
      reading |= static_cast<uint32_t>(telegram[pos + i]) << (8 * i);
    }
    
    // Calculate volume in cubic meters
    double volume = static_cast<double>(reading);
    if (exp < 0) {
      volume /= pow(10, -exp);
    } else if (exp > 0) {
      volume *= pow(10, exp);
    }
    volume /= 1000.0; // Convert from liters to cubic meters
    
    ESP_LOGI(TAG, "ApatorNa1 debug: pos=%d, dif=0x%02X, len=%d, exp=%d, reading=%u, volume=%.3f m³",
             pos, dif, data_len, exp, reading, volume);
    
    return volume;
    
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
