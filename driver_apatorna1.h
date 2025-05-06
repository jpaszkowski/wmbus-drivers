/*
  Based on: https://github.com/wmbusmeters/wmbusmeters/blob/master/src/driver_apatorna1.cc
  Copyright (C) 2017-2022 Fredrik Öhrström (gpl-3.0-or-later)
*/
#pragma once
#include "driver.h"
#include <vector>
#include <string>
#include <cmath>

struct ApatorNa1: Driver
{
  ApatorNa1(std::string key = "") : Driver(std::string("apatorna1"), key) {};

  virtual esphome::optional<std::map<std::string, double>> get_values(std::vector<unsigned char> &telegram) override {
    std::map<std::string, double> ret_val{};

    add_to_map(ret_val, "total_m3", this->get_total_water_m3(telegram));

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

    // Extract payload - we need content from position 2 onwards
    std::vector<unsigned char> frame;
    if (telegram.size() < 4) {
      ESP_LOGW(TAG, "Telegram too short for Apator Na1");
      return {};
    }

    // Extract frame (positions 2-17 from payload)
    size_t start_pos = 2;  // Start at byte 2, as per original code
    size_t end_pos = telegram.size();
    
    if (start_pos + 16 <= telegram.size()) {
      frame.assign(telegram.begin() + start_pos, telegram.begin() + std::min(end_pos, telegram.size()));
    } else {
      ESP_LOGW(TAG, "Telegram too short to extract frame for Apator Na1");
      return {};
    }

    // Extract the multiplier from byte 1 (shift bits as per original code)
    int multiplier = pow(10, (frame.at(1) & 0b00110000) >> 4);

    // Extract the reading from bytes 1-4
    int reading = static_cast<int>(frame.at(3)) << 20 |
                  static_cast<int>(frame.at(2)) << 12 |
                  static_cast<int>(frame.at(1)) << 4  |
                  (static_cast<int>(frame.at(0)) & 0b00001111);  // Adjusted frame indexing

    // Calculate volume in m3
    double volume = static_cast<double>(reading) * multiplier / 1000;

    // Debug log similar to original
    ESP_LOGD(TAG, "Volume: %.3f m3", volume);

    ret_val = volume;

    return ret_val;
  };
};
