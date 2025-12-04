#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdlib> 
#include <sstream>

#include <openfhe.h>

#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <key/key-ser.h>
#include <scheme/bfvrns/bfvrns-ser.h>

// xxd -i key_priv.bin > key_priv.h 
#include "key_priv.h"
// xxd -i key_pub.bin > key_pub.h
#include "key_pub.h"

#include <android/log.h>

#define LOG_TAG "FHERustNativeModule"

static lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = nullptr;

std::vector<float> convertToFloat(const std::vector<double>& doubleVec) {
    std::vector<float> floatVec;
    floatVec.reserve(doubleVec.size());
    std::transform(doubleVec.begin(), doubleVec.end(), std::back_inserter(floatVec),
                   [](double val) { return static_cast<float>(val); });
    return floatVec;
}

std::vector<double> convertToDouble(const std::vector<float>& floatVec) {
    std::vector<double> doubleVec;
    doubleVec.reserve(floatVec.size());
    std::transform(floatVec.begin(), floatVec.end(), std::back_inserter(doubleVec),
                   [](float val) { return static_cast<double>(val); });
    return doubleVec;
}

extern "C" {

struct ByteBuffer {
    uint8_t* ptr;
    size_t len;
};

struct FloatBuffer {
    float* ptr;
    size_t len;
};

struct KeyPair {
    ByteBuffer publicKey;
    ByteBuffer secretKey;
};

void createCryptoContext() {
    if (cryptoContext) {
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Initializing crypto context");

    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(0);
    parameters.SetSecurityLevel(lbcrypto::HEStd_128_quantum);
    parameters.SetScalingModSize(42);
    parameters.SetSecretKeyDist(lbcrypto::UNIFORM_TERNARY);
    parameters.SetFirstModSize(parameters.GetScalingModSize() + 1);
    parameters.SetKeySwitchTechnique(lbcrypto::BV);
    parameters.SetScalingTechnique(lbcrypto::FLEXIBLEAUTO);
    parameters.SetRingDim(1 << 11);
    parameters.SetDesiredPrecision(24);

    cryptoContext = lbcrypto::GenCryptoContext(parameters);

    cryptoContext->Enable(lbcrypto::PKE);
    cryptoContext->Enable(lbcrypto::KEYSWITCH);
    cryptoContext->Enable(lbcrypto::LEVELEDSHE);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Crypto context created");
}

KeyPair generateKeys() {
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Generating keys");

    lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey;
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey;

    // lbcrypto::KeyPair<lbcrypto::DCRTPoly> kp = cryptoContext->KeyGen();
    // publicKey = kp.publicKey;
    // secretKey = kp.secretKey;

    // using static keys for now can we swapped with generation by uncommenting the code above
    std::string pubKeyStr(reinterpret_cast<const char*>(key_pub_bin), key_pub_bin_len);
    std::istringstream pubKeyIss(pubKeyStr);
    lbcrypto::Serial::Deserialize(publicKey, pubKeyIss, lbcrypto::SerType::BINARY);

    std::string privKeyStr(reinterpret_cast<const char*>(key_priv_bin), key_priv_bin_len);
    std::istringstream privKeyIss(privKeyStr);
    lbcrypto::Serial::Deserialize(secretKey, privKeyIss, lbcrypto::SerType::BINARY);

    KeyPair keys;

    std::ostringstream pubOss;
    lbcrypto::Serial::Serialize(publicKey, pubOss, lbcrypto::SerType::BINARY);
    std::string pubStr = pubOss.str();
    keys.publicKey.len = pubStr.size();
    keys.publicKey.ptr = static_cast<uint8_t*>(std::malloc(keys.publicKey.len));
    std::memcpy(keys.publicKey.ptr, pubStr.data(), keys.publicKey.len);

    std::ostringstream privOss;
    lbcrypto::Serial::Serialize(secretKey, privOss, lbcrypto::SerType::BINARY);
    std::string privStr = privOss.str();
    keys.secretKey.len = privStr.size();
    keys.secretKey.ptr = static_cast<uint8_t*>(std::malloc(keys.secretKey.len));
    std::memcpy(keys.secretKey.ptr, privStr.data(), keys.secretKey.len);

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Keys generated");

    return keys;
}

ByteBuffer encrypt(const float* inputData, size_t len, const uint8_t* pubKeyPtr, size_t pubKeyLen) {
    try {
        lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey;
        std::string pubKeyStr(reinterpret_cast<const char*>(pubKeyPtr), pubKeyLen);
        std::istringstream pubKeyIss(pubKeyStr);
        lbcrypto::Serial::Deserialize(publicKey, pubKeyIss, lbcrypto::SerType::BINARY);

        std::vector<float> inputVec(inputData, inputData + len);
        
        lbcrypto::Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(convertToDouble(inputVec));

        auto ciphertext = cryptoContext->Encrypt(publicKey, plaintext);

        std::ostringstream oss;
        lbcrypto::Serial::Serialize(ciphertext, oss, lbcrypto::SerType::BINARY);
        std::string s = oss.str();

        ByteBuffer out;
        out.len = s.size();
        out.ptr = static_cast<uint8_t*>(std::malloc(out.len));
        if (!out.ptr) {
            out.len = 0;
            return out;
        }
        std::memcpy(out.ptr, s.data(), out.len);
        
        return out;
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Exception during encryption: %s", e.what());
        
        throw;
    }
}

FloatBuffer decrypt(const uint8_t* encryptedData, size_t len, const uint8_t* privKeyPtr, size_t privKeyLen) {
    try {
        lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey;
        std::string privKeyStr(reinterpret_cast<const char*>(privKeyPtr), privKeyLen);
        std::istringstream privKeyIss(privKeyStr);
        lbcrypto::Serial::Deserialize(secretKey, privKeyIss, lbcrypto::SerType::BINARY);

        std::string s(reinterpret_cast<const char*>(encryptedData), len);
        std::istringstream iss(s);

        lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertext;
        lbcrypto::Serial::Deserialize(ciphertext, iss, lbcrypto::SerType::BINARY);

        lbcrypto::Plaintext plaintext;
        cryptoContext->Decrypt(secretKey, ciphertext, &plaintext);

        plaintext->SetLength(plaintext->GetLength());
        std::vector<double> decoded = plaintext->GetRealPackedValue();
        std::vector<float> output = convertToFloat(decoded);

        FloatBuffer out;
        out.len = output.size();
        out.ptr = static_cast<float*>(std::malloc(out.len * sizeof(float)));
        if (!out.ptr) {
            out.len = 0;
            return out;
        }
        std::memcpy(out.ptr, output.data(), out.len * sizeof(float));

        return out;
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Exception during decryption: %s", e.what());
        
        throw;
    }
}

void freeByteBuffer(uint8_t* ptr) {
    std::free(ptr);
}

void freeFloatBuffer(float* ptr) {
    std::free(ptr);
}

void freeKeyPair(KeyPair keys) {
    std::free(keys.publicKey.ptr);
    std::free(keys.secretKey.ptr);
}

}
