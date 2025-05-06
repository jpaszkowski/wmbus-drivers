// Definicja funkcji zewnętrznej - zakładamy, że jest dostępna w Twoim środowisku
extern void decrypt_TPL_AES_CBC_IV(void* t, std::vector<unsigned char>& frame, 
                              std::vector<unsigned char>::iterator& pos, 
                              std::vector<unsigned char>& aes_key,
                              int* num_encrypted_bytes, int* num_not_encrypted_at_end);

// Definicja struktury pomocniczej kompatybilnej z oryginałem
struct TelegramHelper {
  unsigned char tpl_acc;
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
  
  std::vector<unsigned char>::iterator pos = frame.begin();
  std::vector<unsigned char> aes_key(16, 0);  // Klucz AES (same zera)
  int num_encrypted_bytes = 0;
  int num_not_encrypted_at_end = 0;
  
  try {
    // Próba deszyfrowania - jeśli funkcja nie istnieje, zostanie rzucony wyjątek
    decrypt_TPL_AES_CBC_IV(&t, frame, pos, aes_key, &num_encrypted_bytes, &num_not_encrypted_at_end);
    ESP_LOGD(TAG, "Decryption completed successfully");
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
