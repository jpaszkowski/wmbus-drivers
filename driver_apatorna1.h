#pragma once
#include "driver.h"
#include <vector>
#include <string>
#include <cmath>
#include <utils.h>

struct ApatorNa1 : Driver
{
  ApatorNa1(std::string key = "") : Driver(std::string("apatorna1"), key) {};

  virtual esphome::optional<std::map<std::string, double>> get_values(std::vector<unsigned char> &telegram) override
  {
    std::map<std::string, double> ret_val{};

    add_to_map(ret_val, "total_m3", this->get_total_water_m3(telegram));

    if (ret_val.size() > 0)
    {
      return ret_val;
    }
    else
    {
      return {};
    }
  };

  esphome::optional<double> get_total_water_m3(std::vector<unsigned char> &telegram) {
    esphome::optional<double> ret_val{};
    
    // Sprawdzenie długości telegramu
    if (telegram.size() < 4) {
      ESP_LOGW(TAG, "Telegram too short for Apator Na1");
      return {};
    }
    
    // Extract frame (positions 2-17 from payload)
    std::vector<unsigned char> frame;
    size_t start_pos = 2;
    
    if (start_pos + 16 <= telegram.size()) {
      frame.assign(telegram.begin() + start_pos, telegram.begin() + start_pos + 16);
    } else {
      ESP_LOGW(TAG, "Telegram too short to extract frame for Apator Na1");
      return {};
    }
    
    // Przygotowanie danych do deszyfrowania
    TelegramHelper t;
    t.tpl_acc = telegram[0];
    
    std::vector<unsigned char> aes_key(16, 0);  // Klucz AES (same zera)
    
    try {
      // Wywołanie dostępnej metody deszyfrującej
      bool decrypt_success = decrypt_TPL_AES_CBC_IV(frame, aes_key);
      if (decrypt_success) {
        ESP_LOGD(TAG, "Decryption completed successfully");
      } else {
        ESP_LOGW(TAG, "Decryption failed");
        // Kontynuujemy z niezdeszyfrowanymi danymi
      }
    } catch (const std::exception& e) {
      ESP_LOGW(TAG, "Decryption exception: %s", e.what());
      // Kontynuujemy bez deszyfrowania
    }
    
    // Obliczanie mnożnika
    int multiplier = pow(10, (frame.at(1) & 0b00110000) >> 4);
    
    // Odczyt wartości licznika
    int reading = static_cast<int>(frame.at(4)) << 20 |
                  static_cast<int>(frame.at(3)) << 12 |
                  static_cast<int>(frame.at(2)) << 4  |
                  (static_cast<int>(frame.at(1)) & 0b00001111);
    
    // Obliczenie objętości w m3
    double volume = static_cast<double>(reading) * multiplier / 1000;
    
    ESP_LOGD(TAG, "Volume: %.3f m3", volume);
    ret_val = volume;
    return ret_val;
  }
};
