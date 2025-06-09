#pragma once

#include "driver.h"
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <algorithm>
#include <memory.h>

namespace esphome {
namespace wmbus {

// Forward declaration of the AES_CBC_decrypt_buffer function from aes.h
extern "C" void AES_CBC_decrypt_buffer(unsigned char* output, unsigned char* input, unsigned int length, const unsigned char* key, const unsigned char* iv);

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
  // Helper function to print hex representation of a vector for debugging
  void print_hex(const std::vector<unsigned char>& data, const std::string& label = "") {
    std::string hex;
    for (const auto& byte : data) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02X", byte);
      hex += buf;
    }
    if (!label.empty()) {
      ESP_LOGI(TAG, "%s: %s", label.c_str(), hex.c_str());
    } else {
      ESP_LOGI(TAG, "%s", hex.c_str());
    }
  }

  // Custom AES-CBC-IV decryption function specifically for Apator NA-1
  bool decrypt_apator_aes_cbc_iv(const std::vector<unsigned char>& input,
                                std::vector<unsigned char>& output,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& telegram)
  {
    // Check if we have enough data to decrypt
    if (input.size() < 16) {
      ESP_LOGE(TAG, "Input too small for decryption");
      return false;
    }

    // Create IV using similar logic to original implementation
    // 1. First 8 bytes are manufacturer and device ID (A-field and M-field in original)
    // 2. Last 8 bytes are the first byte of payload (ACC in original) repeated
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
    
    print_hex(iv, "Generated IV");
    
    // Make sure input size is multiple of 16 (AES block size)
    size_t num_bytes_to_decrypt = (input.size() / 16) * 16;
    
    // Initialize output vector
    output.resize(input.size());
    
    // Perform decryption using the built-in AES_CBC_decrypt_buffer function
    std::vector<unsigned char> input_copy = input;
    
    // Decrypt the data
    AES_CBC_decrypt_buffer(output.data(), 
                           const_cast<unsigned char*>(input_copy.data()), 
                           num_bytes_to_decrypt,
                           key.data(), 
                           iv.data());
    
    // If there are unencrypted bytes at the end, copy them
    if (input.size() > num_bytes_to_decrypt) {
      memcpy(output.data() + num_bytes_to_decrypt, 
             input.data() + num_bytes_to_decrypt, 
             input.size() - num_bytes_to_decrypt);
    }
    
    return true;
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
      ESP_LOGE(TAG, "ApatorNa1: telegram too short to contain CI field");
      return {};
    }
    
    // Print the full telegram for debugging
    print_hex(telegram, "ApatorNa1: Raw telegram");
    
    // Check if we have manufacturer-specific data (CI field = 0xA0 or 0xA1)
    if (telegram[CI_IDX] != 0xA0 && telegram[CI_IDX] != 0xA1) {
      ESP_LOGE(TAG, "ApatorNa1: CI field 0x%02X is not 0xA0/0xA1 (manufacturer specific)", telegram[CI_IDX]);
      return {};
    }
    
    ESP_LOGI(TAG, "ApatorNa1: CI field is 0x%02X - telegram is valid format", telegram[CI_IDX]);

    // Extract payload from telegram (everything after CI field)
    std::vector<unsigned char> payload;
    for (size_t i = CI_IDX + 1; i < telegram.size(); i++) {
      payload.push_back(telegram[i]);
    }
    
    print_hex(payload, "ApatorNa1: Payload");
    
    // Check if payload is large enough
    if (payload.size() < 4) {
      ESP_LOGE(TAG, "ApatorNa1: Payload too small");
      return {};
    }

    // Create frame from payload bytes 2-18 for decryption
    std::vector<unsigned char> frame;
    size_t max_size = std::min(payload.size(), static_cast<size_t>(18));
    for (size_t i = 2; i < max_size; i++) {
      frame.push_back(payload[i]);
    }
    
    print_hex(frame, "ApatorNa1: Frame before decryption");
    
    // Create all-zeros AES key (as used in original wmbusmeters implementation)
    std::vector<unsigned char> aes_key(16, 0);
    
    // Decrypt the frame using our custom function
    std::vector<unsigned char> decrypted_frame;
    if (!decrypt_apator_aes_cbc_iv(frame, decrypted_frame, aes_key, telegram)) {
      ESP_LOGE(TAG, "ApatorNa1: decryption failed with all-zeros key");
      return {};
    }
    
    print_hex(decrypted_frame, "ApatorNa1: Decrypted frame");
    
    // Check if we have enough data to extract readings
    if (decrypted_frame.size() < 5) {
      ESP_LOGE(TAG, "ApatorNa1: decrypted frame too short");
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
    
    ESP_LOGI(TAG, "ApatorNa1: multiplier=%d, reading=%u, volume=%.3f m³",
            multiplier, reading, volume);
            
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
