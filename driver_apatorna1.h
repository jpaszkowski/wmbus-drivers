esphome::optional<double> get_total_water_m3(std::vector<unsigned char> &telegram) {
  esphome::optional<double> ret_val{};
  const char* TAG = "apator_na1"; // Dodane dla logów
  
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
  
  // Tworzymy kopię ramki do deszyfrowania
  std::vector<unsigned char> decrypted_frame(frame.size());
  
  try {
    // Przygotowanie klucza AES (same zera)
    std::vector<unsigned char> aes_key(16, 0);
    
    // Wektor inicjalizacyjny (IV) - również same zera dla prostoty
    // Możesz dostosować IV zgodnie z wymaganiami protokołu
    std::vector<unsigned char> iv(16, 0);
    
    // Deszyfrowanie przy użyciu dostępnej funkcji AES_CBC_decrypt_buffer
    AES_CBC_decrypt_buffer(
      decrypted_frame.data(),    // output
      frame.data(),              // input
      frame.size(),              // length
      aes_key.data(),            // key
      iv.data()                  // iv
    );
    
    ESP_LOGD(TAG, "Decryption completed successfully");
    
    // Po deszyfrowaniu używamy zdekodowanej ramki zamiast oryginalnej
    frame = decrypted_frame;
    
  } catch (const std::exception& e) {
    ESP_LOGW(TAG, "Decryption failed: %s", e.what());
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
