/*
  Based on apator_test.cpp implementation for Apator NA-1 water meter
*/

#pragma once

#include "driver.h"

// For standalone testing without ESPHome
#ifndef ESP_LOGV
#define ESP_LOGV(tag, format, ...) printf(format "\n", ##__VA_ARGS__)
#define ESP_LOGVV(tag, format, ...) printf(format "\n", ##__VA_ARGS__)
#endif

// For standalone testing, include OpenSSL
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#endif

#include "esphome/components/wmbus/aes.h"

#include <vector>
#include <string>
#include <cmath>
#include <cstring> // For memcpy

struct ApatorNa1: Driver
{
  ApatorNa1(std::string key = "") : Driver(std::string("apatorna1"), key) {};
  
  virtual esphome::optional<std::map<std::string, double>> get_values(std::vector<unsigned char> &telegram) override {
    std::map<std::string, double> ret_val{};

    add_to_map(ret_val, "total_water_m3", this->get_total_water_m3(telegram));

    if (ret_val.size() > 0) {
      return ret_val;
    }
    else {
      return {};
    }
  };

private:
  esphome::optional<double> get_total_water_m3(std::vector<unsigned char> &telegram) {
    esphome::optional<double> ret_val{};
    
    // The CI field is at index 10 in the full telegram
    constexpr size_t CI_IDX = 10;
    
    // Check if telegram is long enough to contain CI field
    if (CI_IDX >= telegram.size()) {
      ESP_LOGV(TAG, "Telegram too short to contain CI field");
      return {};
    }
    
    // Check if we have manufacturer-specific data (CI field = 0xA0 or 0xA1)
    if (telegram[CI_IDX] != 0xA0 && telegram[CI_IDX] != 0xA1) {
      ESP_LOGV(TAG, "CI field 0x%02x is not 0xA0/0xA1 (manufacturer specific)", telegram[CI_IDX]);
      return {};
    }
    
    // Extract payload from telegram (similar to extractPayload)
    std::vector<unsigned char> payload;
    for (size_t i = CI_IDX + 1; i < telegram.size(); i++) {
      payload.push_back(telegram[i]);
    }
    
    ESP_LOGVV(TAG, "Extracted payload (size %d)", payload.size());
    ESP_LOGD(TAG, "Payload hex: ");
    for (size_t i = 0; i < payload.size(); ++i) {
      ESP_LOGD(TAG, "[%02zu]: 0x%02X", i, payload[i]);
    }
    
    // For A1 telegrams, check the structure
    if (telegram[CI_IDX] == 0xA1) {
      ESP_LOGD(TAG, "A1 format detected - treating payload differently");
    }
    
    // Check if payload is large enough
    if (payload.size() < 4) {
      ESP_LOGV(TAG, "Payload too small");
      return {};
    }
    
    // Create frame from payload bytes 2-18 (like in original implementation)
    std::vector<unsigned char> frame;
    
    // Handling depends on the CI field format
    if (telegram[CI_IDX] == 0xA0) {
      // Standard format from original implementation
      for (size_t i = 2; i < std::min(payload.size(), static_cast<size_t>(18)); i++) {
        frame.push_back(payload[i]);
      }
    } else if (telegram[CI_IDX] == 0xA1) {
      // A1 format - dla telegramów A1 przesunięcie wynosi 2 bajty
      // Dane zaczynają się od trzeciego bajtu po CI
      if (payload.size() >= 3) {  // Upewnij się, że mamy co najmniej 3 bajty w payloadzie
        for (size_t i = 2; i < std::min(payload.size(), static_cast<size_t>(18)); i++) {
          frame.push_back(payload[i]);
        }
        ESP_LOGD(TAG, "Extracted A1 format frame, starting from third byte of payload");
      } else {
        ESP_LOGD(TAG, "A1 payload too small");
        return {};
      }
    }
    
    ESP_LOGVV(TAG, "Extracted frame before decryption, size: %d", frame.size());
    
    // Decrypt frame using AES-CBC-IV with key "00000000000000000000000000000000"
    std::vector<unsigned char> aes_key(16, 0);  // All zeros key
    std::vector<unsigned char> decrypted_frame;
    
    // Process and decrypt the frame
    bool decryption_success = decrypt_frame(frame, decrypted_frame, aes_key, telegram);
    
    if (!decryption_success) {
      ESP_LOGV(TAG, "Decryption failed");
      return {};
    }
    
    // Calculate water consumption from decrypted frame
    if (decrypted_frame.size() < 5) {
      ESP_LOGV(TAG, "Decrypted frame too short");
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
    
    ESP_LOGV(TAG, "Apator NA-1: Multiplier: %d, Reading: %u, Volume: %.3f m³", 
             multiplier, reading, volume);
    
    ret_val = volume;
    return ret_val;
  };

  // AES-CBC-IV decryption function for Apator NA-1
  bool decrypt_frame(const std::vector<unsigned char>& input,
                    std::vector<unsigned char>& output,
                    const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& telegram) {
    // Check if we have enough data to decrypt
    if (input.size() < 16) {
      ESP_LOGV(TAG, "Input too small for decryption");
      return false;
    }

    // Create IV using manufacturer and device ID fields
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
    
    ESP_LOGVV(TAG, "Generated IV for AES decryption");
    
    // Make sure input size is multiple of 16 (AES block size)
    size_t num_bytes_to_decrypt = (input.size() / 16) * 16;
    
    // Initialize output vector
    output.resize(input.size());

#ifdef USE_OPENSSL
    // Use OpenSSL for standalone testing
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ESP_LOGV(TAG, "Error creating cipher context");
        return false;
    }
    
    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data())) {
        ESP_LOGV(TAG, "Error initializing decryption");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform decryption
    int outlen;
    if (1 != EVP_DecryptUpdate(ctx, output.data(), &outlen, input.data(), num_bytes_to_decrypt)) {
        ESP_LOGV(TAG, "Error during decryption");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize decryption
    int tmplen;
    if (1 != EVP_DecryptFinal_ex(ctx, output.data() + outlen, &tmplen)) {
        // This might fail due to padding, but we can ignore it since we don't use padding
        ESP_LOGV(TAG, "Warning: Finalization failed, but continuing anyway");
    }
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
#else
    // Use ESPHome AES implementation
    esphome::wmbus::AES_CBC_decrypt_buffer(output.data(), const_cast<unsigned char*>(input.data()), 
                                           num_bytes_to_decrypt, key.data(), iv.data());
#endif
    
    // If there are unencrypted bytes at the end, copy them
    size_t num_not_encrypted_at_end = input.size() - num_bytes_to_decrypt;
    if (num_not_encrypted_at_end > 0) {
      memcpy(output.data() + num_bytes_to_decrypt, 
             input.data() + num_bytes_to_decrypt, 
             num_not_encrypted_at_end);
    }
    
    return true;
  }
};