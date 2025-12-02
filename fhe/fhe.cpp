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

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = nullptr;
lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey;
lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey;

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

void createCryptoContext() {
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

    lbcrypto::KeyPair<lbcrypto::DCRTPoly> kp = cryptoContext->KeyGen();
    publicKey = kp.publicKey;
    secretKey = kp.secretKey;
}

ByteBuffer encrypt(const float* inputData, size_t len) {
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
}

FloatBuffer decrypt(const uint8_t* encryptedData, size_t len) {
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
}

void freeByteBuffer(uint8_t* ptr, size_t) {
    std::free(ptr);
}

void freeFloatBuffer(float* ptr, size_t) {
    std::free(ptr);
}

}
