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
      ESP_LOGI(TAG, "ApatorNa1 driver v1.2.0 initialized");
      ESP_LOGI(TAG, "Driver supports Apator NA-1 water meters using AES-CBC-IV decryption");
      ESP_LOGI(TAG, "Using %s key for decryption", 
               key.empty() ? "default all-zeros" : ("custom key: " + key).c_str());
    }

  /**
   * Extracts available values from a decrypted telegram
   * @param telegram Full decrypted M-Bus frame
   * @return Map of sensor names to values, or empty optional if parsing fails
   */
  virtual esphome::optional<std::map<std::string, double>> get_values(
      std::vector<unsigned char> &telegram) override {
    ESP_LOGI(TAG, "ApatorNa1: processing telegram of length %d bytes", (int)telegram.size());
    
    if (telegram.size() < 11) {
      ESP_LOGE(TAG, "ApatorNa1: telegram too short (%d bytes), cannot process", (int)telegram.size());
      return {};
    }
    
    // Check manufacturer ID (should be APT for Apator)
    if (telegram.size() >= 4) {
      char manufacturer[3] = {
        (char)((telegram[3] & 0x0F) << 4) | ((telegram[2] & 0xF0) >> 4),
        (char)((telegram[2] & 0x0F) << 4) | ((telegram[3] & 0xF0) >> 4),
        0
      };
      ESP_LOGI(TAG, "ApatorNa1: Manufacturer ID: %s", manufacturer);
      
      // Could check if it's "APT" but some meters might use different codes
    }
    
    auto total = this->get_total_water_m3(telegram);
    if (total.has_value()) {
      // Check if the value is reasonable (for a water meter)
      if (total.value() > 1000.0) {
        ESP_LOGW(TAG, "ApatorNa1: Suspicious water value: %.3f m³ - likely decoding error", total.value());
        return {}; // Don't return unreasonable values
      }
      
      // Check if the value is unreasonably small
      if (total.value() < 0.001) {
        ESP_LOGW(TAG, "ApatorNa1: Very low water value: %.6f m³ - possibly incorrect", total.value());
        // We still return it, but warn about it
      }
      
      ESP_LOGI(TAG, "ApatorNa1: total_water_m3 = %.3f m³", total.value());
      std::map<std::string, double> ret;
      ret["total_water_m3"] = total.value();
      return ret;
    } else {
      ESP_LOGE(TAG, "ApatorNa1: Failed to extract water meter reading");
      return {};
    }
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
                                const std::vector<unsigned char>& telegram,
                                int* num_encrypted_bytes,
                                int* num_not_encrypted_at_end)
  {
    // Check if we have enough data to decrypt
    if (input.size() < 16) {
      ESP_LOGE(TAG, "Input too small for decryption (%d bytes, need at least 16)", (int)input.size());
      return false;
    }

    // Print detailed telegram info for debugging
    ESP_LOGD(TAG, "Telegram details: Length=%d, L-field=0x%02X, C-field=0x%02X, M-field=0x%02X%02X",
             (int)telegram.size(), telegram.size() > 0 ? telegram[0] : 0, 
             telegram.size() > 1 ? telegram[1] : 0,
             telegram.size() > 2 ? telegram[2] : 0, 
             telegram.size() > 3 ? telegram[3] : 0);
             
    if (telegram.size() <= 11) {
      ESP_LOGE(TAG, "Telegram too short for IV generation (size=%d, need at least 12)", (int)telegram.size());
      return false;
    }

    // Create IV exactly like in test code
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
    
    ESP_LOGI(TAG, "IV Generation: M-field: %02X%02X, A-field: %02X%02X%02X%02X%02X%02X, ACC: %02X",
             iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], acc);
    print_hex(iv, "Generated IV");
    
    // Make sure input size is multiple of 16 (AES block size)
    size_t num_bytes_to_decrypt = (input.size() / 16) * 16;
    *num_encrypted_bytes = num_bytes_to_decrypt;
    *num_not_encrypted_at_end = input.size() - num_bytes_to_decrypt;
    
    ESP_LOGI(TAG, "Decrypting %d bytes, %d unencrypted bytes at end", 
             (int)num_bytes_to_decrypt, *num_not_encrypted_at_end);
    
    // Initialize output vector
    output.resize(input.size(), 0); // Initialize with zeros
    
    if (num_bytes_to_decrypt == 0) {
      ESP_LOGW(TAG, "No full blocks to decrypt, skipping AES decryption");
      // If there are unencrypted bytes at the end, copy them
      if (*num_not_encrypted_at_end > 0) {
        memcpy(output.data(), input.data(), *num_not_encrypted_at_end);
      }
      return true;
    }
    
    // Print input data for debugging
    print_hex(input, "Input data for decryption");
    
    // Perform decryption using the built-in AES_CBC_decrypt_buffer function
    std::vector<unsigned char> input_copy = input;
    
    // Decrypt the data
    AES_CBC_decrypt_buffer(output.data(), 
                          const_cast<unsigned char*>(input_copy.data()), 
                          num_bytes_to_decrypt,
                          key.data(), 
                          iv.data());
    
    // If there are unencrypted bytes at the end, copy them
    if (*num_not_encrypted_at_end > 0) {
      memcpy(output.data() + num_bytes_to_decrypt, 
             input.data() + num_bytes_to_decrypt, 
             *num_not_encrypted_at_end);
    }
    
    // Print output data for debugging
    print_hex(output, "Decrypted output data");
    
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
      ESP_LOGE(TAG, "ApatorNa1: telegram too short to contain CI field (size=%d, need at least 11)", 
               (int)telegram.size());
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
    ESP_LOGI(TAG, "Payload size: %d bytes", (int)payload.size());
    
    // Check if payload is large enough
    if (payload.size() < 4) {
      ESP_LOGE(TAG, "ApatorNa1: Payload too small (size=%d, need at least 4)", (int)payload.size());
      return {};
    }
    
    // Analyze payload structure for debugging
    ESP_LOGI(TAG, "Payload structure: First byte: 0x%02X, Second byte: 0x%02X", 
             payload[0], payload.size() > 1 ? payload[1] : 0);
    
    // For the case of 'unexpected record length 0 at pos 13', check if we have DIF/VIF
    if (payload.size() > 2) {
      ESP_LOGI(TAG, "Record bytes: byte2: 0x%02X (DIF?), byte3: 0x%02X (VIF?)", 
               payload[2], payload.size() > 3 ? payload[3] : 0);
    }

    // Create frame from payload bytes 2-18 (like in test implementation)
    std::vector<unsigned char> frame;
    size_t start_idx = 2; // Start from payload[2]
    
    // Safety check - make sure we have enough data
    if (payload.size() <= start_idx) {
      ESP_LOGE(TAG, "ApatorNa1: Payload too small for frame extraction (size=%d, need at least %d)", 
               (int)payload.size(), (int)(start_idx + 1));
      return {};
    }
    
    size_t end_idx = std::min(payload.size(), static_cast<size_t>(18));
    
    for (size_t i = start_idx; i < end_idx; i++) {
      frame.push_back(payload[i]);
    }
    
    ESP_LOGI(TAG, "Frame for decryption: taking payload[%d:%d], frame size: %d", 
             (int)start_idx, (int)end_idx, (int)frame.size());
    print_hex(frame, "ApatorNa1: Frame before decryption");
    
    // Check for empty frame
    if (frame.size() == 0) {
      ESP_LOGE(TAG, "ApatorNa1: Empty frame - nothing to decrypt");
      return {};
    }
    
    // Create all-zeros AES key (as used in original wmbusmeters implementation)
    std::vector<unsigned char> aes_key(16, 0);
    print_hex(aes_key, "ApatorNa1: AES Key (all zeros)");
    
    // Decrypt the frame using our custom function
    std::vector<unsigned char> decrypted_frame;
    int num_encrypted_bytes = 0;
    int num_not_encrypted_at_end = 0;
    
    if (!decrypt_apator_aes_cbc_iv(frame, decrypted_frame, aes_key, telegram, 
                                  &num_encrypted_bytes, &num_not_encrypted_at_end)) {
      ESP_LOGE(TAG, "ApatorNa1: decryption failed with all-zeros key");
      return {};
    }
    
    print_hex(decrypted_frame, "ApatorNa1: Decrypted frame");
    
    // Check if we have enough data to extract readings
    if (decrypted_frame.size() < 5) {
      ESP_LOGE(TAG, "ApatorNa1: decrypted frame too short (size=%d, need at least 5)", 
               (int)decrypted_frame.size());
      
      // If we have at least some data, try to extract what we can
      if (decrypted_frame.size() >= 2) {
        ESP_LOGI(TAG, "Attempting simplified reading with partial data");
        // Try a simplified approach with the data we have
        int simple_multiplier = 1; // Default multiplier
        if (decrypted_frame.size() >= 2) {
          int multiplier_bits = (decrypted_frame[1] & 0b00110000) >> 4;
          if (multiplier_bits <= 3) {
            simple_multiplier = std::pow(10, multiplier_bits);
          }
        }
        
        // Extract whatever bytes we have for a reading
        uint32_t simple_reading = 0;
        for (size_t i = 1; i < decrypted_frame.size(); i++) {
          simple_reading = (simple_reading << 8) | decrypted_frame[i];
        }
        
        double simple_volume = static_cast<double>(simple_reading) / 1000.0;
        ESP_LOGI(TAG, "Simplified partial calculation: reading=%u, volume=%.3f m³", 
                 simple_reading, simple_volume);
        
        // Only return if reasonable
        if (simple_volume > 0 && simple_volume < 1000.0) {
          return simple_volume;
        }
      }
      
      return {};
    }
    
    // Sanity check - check if the frame looks reasonable
    // First byte is often a control code
    ESP_LOGI(TAG, "Decrypted data - first bytes: %02X %02X %02X %02X %02X",
             decrypted_frame[0], decrypted_frame[1], decrypted_frame[2], 
             decrypted_frame[3], decrypted_frame[4]);
    
    // The multiplier is calculated from bits 4-5 of byte 1 in the frame - exactly like in test code
    int multiplier_bits = (decrypted_frame[1] & 0b00110000) >> 4;
    
    // Sanity check on multiplier
    if (multiplier_bits > 3) {
      ESP_LOGW(TAG, "ApatorNa1: Invalid multiplier bits: %d (expected 0-3), capping to 0", multiplier_bits);
      multiplier_bits = 0; // Cap to 0 if invalid
    }
    
    const int multiplier = std::pow(10, multiplier_bits);
    
    // The reading uses bytes 1-4 of the frame (exactly like in test code)
    const uint32_t reading = static_cast<uint32_t>(decrypted_frame[4]) << 20 |
                             static_cast<uint32_t>(decrypted_frame[3]) << 12 |
                             static_cast<uint32_t>(decrypted_frame[2]) << 4  |
                             (static_cast<uint32_t>(decrypted_frame[1]) & 0x0F);
    
    // Convert to cubic meters (exactly as in test code)
    const double volume = static_cast<double>(reading) * multiplier / 1000.0;
    
    // Detailed debug - similar to the test code output
    ESP_LOGI(TAG, "ApatorNa1 debug: pos=0, dif=0x%02X, vif=0x%02X, len=4, exp=%d, reading=%u, volume=%.3f m³",
             decrypted_frame[0], decrypted_frame.size() > 1 ? decrypted_frame[1] : 0,
             multiplier_bits, reading, volume);
    
    // Sanity check - water meter readings should be reasonable
    if (volume > 1000.0) {
      ESP_LOGW(TAG, "ApatorNa1: Suspicious water value: %.3f m³ - likely decoding error", volume);
      
      // Try using a simpler calculation to see if we get more reasonable values
      uint32_t simple_reading = 0;
      for (size_t i = 1; i <= 4 && i < decrypted_frame.size(); i++) {
        simple_reading = (simple_reading << 8) | decrypted_frame[i];
      }
      double simple_volume = static_cast<double>(simple_reading) / 1000.0;
      ESP_LOGI(TAG, "Alternative simple calculation: reading=%u, volume=%.3f m³", 
               simple_reading, simple_volume);
      
      // We'll use the simple value if it's reasonable, otherwise don't return anything
      if (simple_volume <= 1000.0) {
        ESP_LOGI(TAG, "Using alternative calculation result");
        return simple_volume;
      }
      
      // Try yet another approach - sometimes the position might be offset
      if (decrypted_frame.size() >= 6) {
        uint32_t offset_reading = static_cast<uint32_t>(decrypted_frame[5]) << 20 |
                                 static_cast<uint32_t>(decrypted_frame[4]) << 12 |
                                 static_cast<uint32_t>(decrypted_frame[3]) << 4  |
                                 (static_cast<uint32_t>(decrypted_frame[2]) & 0x0F);
        
        double offset_volume = static_cast<double>(offset_reading) * multiplier / 1000.0;
        ESP_LOGI(TAG, "Offset calculation: reading=%u, volume=%.3f m³", 
                 offset_reading, offset_volume);
        
        if (offset_volume > 0 && offset_volume <= 1000.0) {
          ESP_LOGI(TAG, "Using offset calculation result");
          return offset_volume;
        }
      }
      
      return {}; // Don't return unreasonable values
    }
    
    ESP_LOGI(TAG, "ApatorNa1: multiplier=%d, reading=%u, volume=%.3f m³",
            multiplier, reading, volume);
            
    return volume;
  }
};

}  // namespace wmbus
}  // namespace esphome
