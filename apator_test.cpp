#include <vector>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cassert>
#include <algorithm> // Add this for std::remove

// OpenSSL includes for AES decryption
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

// Type alias for unsigned char
using uchar = unsigned char;

// Function to print a byte vector as hex
void print_hex(const std::vector<uchar>& data, const std::string& label = "") {
    if (!label.empty()) {
        std::cout << label << ": ";
    }
    for (const auto& byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

// AES-CBC-IV decryption function - improved to match original implementation
bool decrypt_TPL_AES_CBC_IV(const std::vector<uchar>& input,
                            std::vector<uchar>& output,
                            const std::vector<uchar>& key,
                            const std::vector<uchar>& telegram,
                            int* num_encrypted_bytes,
                            int* num_not_encrypted_at_end)
{
    // Check if we have enough data to decrypt
    if (input.size() < 16) {
        std::cerr << "Input too small for decryption" << std::endl;
        return false;
    }

    // Create IV using similar logic to original implementation
    // For simplicity we'll use a more basic approach:
    // 1. First 8 bytes are manufacturer and device ID (A-field and M-field in original)
    // 2. Last 8 bytes are the first byte of payload (ACC in original) repeated
    std::vector<uchar> iv(16, 0);
    
    // First 2 bytes: manufacturer (M-field)
    iv[0] = telegram[2]; // Manufacturer byte 1
    iv[1] = telegram[3]; // Manufacturer byte 2
    
    // Next 6 bytes: device ID (A-field)
    for (int i = 0; i < 6; ++i) {
        iv[i+2] = telegram[4+i]; // Device ID bytes
    }
    
    // Last 8 bytes: payload[0] repeated (ACC)
    uchar acc = telegram[11]; // First byte after CI field
    for (int i = 0; i < 8; ++i) {
        iv[i+8] = acc;
    }
    
    std::cout << "Generated IV: ";
    print_hex(iv);
    
    // Make sure input size is multiple of 16 (AES block size)
    size_t num_bytes_to_decrypt = (input.size() / 16) * 16;
    *num_encrypted_bytes = num_bytes_to_decrypt;
    *num_not_encrypted_at_end = input.size() - num_bytes_to_decrypt;
    
    // Initialize output vector
    output.resize(input.size());
    
    // Prepare AES context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return false;
    }
    
    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data())) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform decryption
    int outlen;
    if (1 != EVP_DecryptUpdate(ctx, output.data(), &outlen, input.data(), num_bytes_to_decrypt)) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize decryption
    int tmplen;
    if (1 != EVP_DecryptFinal_ex(ctx, output.data() + outlen, &tmplen)) {
        // This might fail due to padding, but we can ignore it since we don't use padding
        std::cerr << "Warning: Finalization failed, but continuing anyway" << std::endl;
    }
    
    // If there are unencrypted bytes at the end, copy them
    if (*num_not_encrypted_at_end > 0) {
        memcpy(output.data() + num_bytes_to_decrypt, 
               input.data() + num_bytes_to_decrypt, 
               *num_not_encrypted_at_end);
    }
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

// Function to extract water consumption from Apator NA-1 telegram
double extract_water_consumption(const std::vector<uchar>& telegram) {
    // The CI field is at index 10 in the full telegram
    constexpr size_t CI_IDX = 10;
    
    // Check if telegram is long enough to contain CI field
    if (CI_IDX >= telegram.size()) {
        std::cout << "Telegram too short to contain CI field" << std::endl;
        return 0.0;
    }
    
    // Check if we have manufacturer-specific data (CI field = 0xA0)
    if (telegram[CI_IDX] != 0xA0) {
        std::cout << "CI field 0x" << std::hex << static_cast<int>(telegram[CI_IDX]) 
                  << " is not 0xA0 (manufacturer specific)" << std::dec << std::endl;
        return 0.0;
    }
    
    // Extract payload from telegram (similar to extractPayload)
    std::vector<uchar> payload;
    for (size_t i = CI_IDX + 1; i < telegram.size(); i++) {
        payload.push_back(telegram[i]);
    }
    
    std::cout << "Extracted payload (size " << payload.size() << "): ";
    print_hex(payload);
    
    // Check if payload is large enough
    if (payload.size() < 4) {
        std::cout << "Payload too small" << std::endl;
        return 0.0;
    }
    
    // Create frame from payload bytes 2-18 (like in original implementation)
    std::vector<uchar> frame;
    for (size_t i = 2; i < std::min(payload.size(), static_cast<size_t>(18)); i++) {
        frame.push_back(payload[i]);
    }
    
    std::cout << "Extracted frame before decryption: ";
    print_hex(frame);
    
    // Decrypt frame using AES-CBC-IV with key "00000000000000000000000000000000"
    std::vector<uchar> aes_key(16, 0);  // All zeros key
    std::vector<uchar> decrypted_frame;
    int num_encrypted_bytes = 0;
    int num_not_encrypted_at_end = 0;
    
    bool decryption_success = decrypt_TPL_AES_CBC_IV(frame, decrypted_frame, aes_key, 
                                                    telegram,
                                                    &num_encrypted_bytes, 
                                                    &num_not_encrypted_at_end);
    
    if (!decryption_success) {
        std::cout << "Decryption failed" << std::endl;
        return 0.0;
    }
    
    std::cout << "Decrypted frame: ";
    print_hex(decrypted_frame);
    
    // Calculate water consumption from decrypted frame
    if (decrypted_frame.size() < 5) {
        std::cout << "Decrypted frame too short" << std::endl;
        return 0.0;
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
    
    std::cout << "Multiplier: " << multiplier << std::endl;
    std::cout << "Reading: " << reading << std::endl;
    std::cout << "Volume: " << volume << " m³" << std::endl;
    
    return volume;
}

// Function to parse a hexadecimal telegram string into bytes
std::vector<uchar> parse_telegram(const std::string& telegram_str) {
    std::vector<uchar> telegram;
    
    // Remove the | characters and any underscores if present
    std::string cleaned = telegram_str;
    cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '|'), cleaned.end());
    cleaned.erase(std::remove(cleaned.begin(), cleaned.end(), '_'), cleaned.end());
    
    // Parse each pair of hex characters as a byte
    for (size_t i = 0; i < cleaned.length(); i += 2) {
        if (i + 1 < cleaned.length()) {
            std::string byte_str = cleaned.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
            telegram.push_back(byte);
        }
    }
    
    return telegram;
}

int main() {
    std::cout << "Starting Apator NA-1 test program (improved)..." << std::endl;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    std::cout << "===== Apator NA-1 Water Meter Telegram Decoder =====" << std::endl;
    std::cout << "Using AES-CBC-IV decryption with all-zeros key and proper IV generation" << std::endl;
    
    // Example 1: Expected value 1.478 m³
    std::string telegram1 = "|1C440106477361071407A0_16013BCCBF8D079415143474030F453A1796|";
    std::cout << "\n\nEXAMPLE 1: " << telegram1 << std::endl;
    std::cout << "Expected value: 1.478 m³" << std::endl;
    auto bytes1 = parse_telegram(telegram1);
    double volume1 = extract_water_consumption(bytes1);
    std::cout << "Result: " << volume1 << " m³" << std::endl;
    
    // Example 2: Expected value 19.067 m³
    std::string telegram2 = "|1C440106797261071407A0_10018EA5881A8C2997D630EA5E55A1974870|";
    std::cout << "\n\nEXAMPLE 2: " << telegram2 << std::endl;
    std::cout << "Expected value: 19.067 m³" << std::endl;
    auto bytes2 = parse_telegram(telegram2);
    double volume2 = extract_water_consumption(bytes2);
    std::cout << "Result: " << volume2 << " m³" << std::endl;
    
    // Example 3: Expected value 345.312 m³
    std::string telegram3 = "|1C440106813591041407A0B000266A705474DDB80D9A0EB9AE2EF29D96|";
    std::cout << "\n\nEXAMPLE 3: " << telegram3 << std::endl;
    std::cout << "Expected value: 345.312 m³" << std::endl;
    auto bytes3 = parse_telegram(telegram3);
    double volume3 = extract_water_consumption(bytes3);
    std::cout << "Result: " << volume3 << " m³" << std::endl;
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
