#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

const int AES_KEY_LENGTH = 256;
const int AES_BLOCK_SIZE = 16;
const int SALT_LENGTH = 16;
const int HASH_ITERATIONS = 10000;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

bool authenticateUser(const std::string& username, const std::string& password) {
    const std::string storedUsername = "user";
    const std::string storedPasswordHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd82a187f64f4e4b118"; // "password" SHA256 hash

    if (username == storedUsername) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password.c_str(), password.length());
        SHA256_Final(hash, &sha256);

        char hashStr[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            sprintf(hashStr + (i * 2), "%02x", hash[i]);
        }
        hashStr[SHA256_DIGEST_LENGTH * 2] = 0;

        return storedPasswordHash == std::string(hashStr);
    }
    return false;
}

void encryptPassword(const std::string& plaintext, std::vector<unsigned char>& ciphertext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE + sizeof(iv));
    std::copy(iv, iv + sizeof(iv), ciphertext.begin());

    if (1 != EVP_EncryptUpdate(ctx, &ciphertext[sizeof(iv)], &len, (unsigned char*)plaintext.c_str(), plaintext.length())) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, &ciphertext[sizeof(iv) + len], &len)) handleErrors();
    ciphertext_len += len;

    ciphertext.resize(sizeof(iv) + ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
}

void decryptPassword(const std::vector<unsigned char>& ciphertext, std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    std::vector<unsigned char> plaintext_buf(ciphertext.size() - AES_BLOCK_SIZE);
    if (1 != EVP_DecryptUpdate(ctx, &plaintext_buf[0], &len, &ciphertext[AES_BLOCK_SIZE], ciphertext.size() - AES_BLOCK_SIZE)) handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, &plaintext_buf[len], &len)) handleErrors();
    plaintext_len += len;

    plaintext_buf.resize(plaintext_len);
    plaintext = std::string(plaintext_buf.begin(), plaintext_buf.end());

    EVP_CIPHER_CTX_free(ctx);
}

std::string generatePassword(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string password;
    password.resize(length);

    for (int i = 0; i < length; ++i) {
        password[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    return password;
}

void storePassword(const std::string& site, const std::string& username, const std::string& password, const unsigned char* key) {
    std::vector<unsigned char> encryptedPassword;
    encryptPassword(password, encryptedPassword, key);

    std::ofstream file("passwords.txt", std::ios::app | std::ios::binary);
    file << site << " " << username << " ";
    for (unsigned char c : encryptedPassword) {
        file << std::hex << (int)c;
    }
    file << std::endl;
    file.close();
}

void retrievePassword(const std::string& site, const std::string& username, const unsigned char* key) {
    std::ifstream file("passwords.txt", std::ios::binary);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string storedSite, storedUsername, encryptedPasswordHex;
        iss >> storedSite >> storedUsername >> encryptedPasswordHex;

        if (storedSite == site && storedUsername == username) {
            std::vector<unsigned char> encryptedPassword(encryptedPasswordHex.length() / 2);
            for (size_t i = 0; i < encryptedPassword.size(); ++i) {
                sscanf(&encryptedPasswordHex[i * 2], "%2hhx", &encryptedPassword[i]);
            }

            std::string decryptedPassword;
            decryptPassword(encryptedPassword, decryptedPassword, key);
            std::cout << "Password for " << site << ": " << decryptedPassword << std::endl;
            return;
        }
    }
    std::cout << "No password found for " << site << std::endl;
}

int main() {
    const std::string key = "01234567890123456789012345678901"; // 32-byte key for AES-256

    std::string username;
    std::string password;
    
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    if (!authenticateUser(username, password)) {
        std::cout << "Authentication failed!" << std::endl;
        return 1;
    }

    int choice;
    do {
        std::cout << "1. Store password" << std::endl;
        std::cout << "2. Retrieve password" << std::endl;
        std::cout << "3. Generate password" << std::endl;
        std::cout << "4. Exit" << std::endl;
        std::cout << "Enter choice: ";
        std::cin >> choice;

        if (choice == 1) {
            std::string site, user, pass;
            std::cout << "Enter site: ";
            std::cin >> site;
            std::cout << "Enter username: ";
            std::cin >> user;
            std::cout << "Enter password: ";
            std::cin >> pass;

            storePassword(site, user, pass, (unsigned char*)key.c_str());
        } else if (choice == 2) {
            std::string site, user;
            std::cout << "Enter site: ";
            std::cin >> site;
            std::cout << "Enter username: ";
            std::cin >> user;

            retrievePassword(site, user, (unsigned char*)key.c_str());
        } else if (choice == 3) {
            int length;
            std::cout << "Enter password length: ";
            std::cin >> length;

            std::string generatedPassword = generatePassword(length);
            std::cout << "Generated password: " << generatedPassword << std::endl;
        }
    } while (choice != 4);

    return 0;
}
