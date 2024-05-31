#include <string>
#include <vector>
#include <cstdint>
#include <iostream>

#include <bitset>

/// \brief Sha2 constants
const std::uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

uint32_t RightRotate(const uint32_t& intToRotate, const uint32_t& rotateSize)
{
    return (intToRotate >> rotateSize) | (intToRotate << (sizeof(uint32_t) * 8 - rotateSize));
}

/// \brief Convert uint32 to string with hex form of this number
/// \param [in] a uint32 number to convert
/// \return hex represenation of a
std::string Uint32ToHexForm(std::uint32_t a) noexcept
{
    std::string res(8, 0);
    
    for (int i = 7; i > -1; i -= 2)
    {
        int highByte = a % 16;
        a /= 16;
        
        int lowByte = a % 16;
        a /= 16;

        if (highByte > 9)
            res[i] = 'a' + highByte - 10;
        else
            res[i] = highByte + '0';

        if (lowByte > 9)
            res[i - 1] = 'a' + lowByte - 10;
        else
            res[i - 1] = lowByte + '0';
    }

    return res;
}

/**
    \brief The function considers the correct padding for the data

    \param [in] data a pointer to the char array to find the padding for
    \param [in] arrayLen the number of elements in the data arr
    \param [in] dataLen the length of the source data

    \return Returns a string with the correct padding of length 64 or 128, depending on the length of the source data
*/
inline std::vector<char> DataPadding_Sha2(const char* data, const std::size_t& dataLen, const std::size_t& sourceLen) noexcept
{
    // String length in bytes
    std::uint64_t stringLength = sourceLen * 8;
    std::vector<char> padding;

    // Set known padding
    for (std::size_t i = 0; i < dataLen; ++i)
        padding.emplace_back(data[i]);

    // Add one 1 bit and seven 0 bits to data end. It's equals adding 10000000 or 128 symbol to string end
    padding.emplace_back(128);

    // Adding additional bits to make data length equal 512*N + 448, or in chars 64*N + 56
    // Adding eight 0 bits to data end. It's equals adding 00000000 or 0 symbol to string end
    while (padding.size() % 64 != 56)
        padding.emplace_back('\0');
    
    // String with source string size
    std::vector<char> stringAddition;

    // Pushing symbols to string. Equals 256 based count system
    while (stringLength / 256 > 0)
    {
        stringAddition.emplace_back(static_cast<char>(stringLength % 256));
        std::cout << stringLength % 256 << std::endl;
        stringLength /= 256;
    } 

    // Add last byte to stringAddition
    stringAddition.emplace_back(static_cast<char>(stringLength % 256));
    std::cout << stringLength % 256 << std::endl;

    // Add zero bytes to padding    
    for (unsigned int i = 0; i < 8 - stringAddition.size(); ++i)
        padding.emplace_back('\0'); 

    // Adding string addition chars to source string in right order
    // At first we add 4 last bytes(chars). After that we add 4 first bytes(chars).
    // Also this function change bytes position to next function CalculateHastStep_MD5
    for (std::size_t i = stringAddition.size() - 1; i != 0; --i)
        padding.emplace_back(stringAddition[i]);
        
    padding.emplace_back(stringAddition[0]);

    return padding;
}

void Sha2Step(const char* data, const std::size_t& dataPos, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4, std::uint32_t& h5, std::uint32_t& h6, std::uint32_t& h7)
{
    // Words array
    std::uint32_t words[64] = {0};

    // Join 4 chars from data into 16 uint32_t numbers and save it to words array
    for (int i = 0; i < 64; i += 4)
        words[i >> 2] = (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + dataPos])) << 24) | 
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 1 + dataPos])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 2 + dataPos])) << 8) | 
            static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 3 + dataPos]));

    // Fill last 48 uint32_t numbers
    for (int i = 16; i < 64; ++i)
        words[i] = words[i - 16] + (RightRotate(words[i - 15], 7) ^ RightRotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] + (RightRotate(words[i - 2], 17) ^ RightRotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // Temple variables
    std::uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    // 64 rounds to calculate hash for data block
    std::uint32_t temp1, temp2;
    for (int i = 0; i < 64; ++i)
    {
        temp1 = h + (RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25)) + ((e & f) ^ ((~e) & g)) + K[i] + words[i];
        temp2 = (RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
}

std::string HashSha2(const char* data, const std::size_t& dataLen)
{
    // Begin hash values
    std::uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    for (std::size_t i = 0; i < dataLen >> 6; ++i)
        Sha2Step(data, i << 6, h0, h1, h2, h3, h4, h5, h6, h7);

    // Padding source string
    std::vector<char> padding = DataPadding_Sha2(data + (dataLen & ~0b00111111), dataLen & 0b00111111, dataLen);

    Sha2Step(padding.data(), 0, h0, h1, h2, h3, h4, h5, h6, h7);

    if (padding.size() > 64)
        Sha2Step(padding.data(), 64, h0, h1, h2, h3, h4, h5, h6, h7);

    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4) + Uint32ToHexForm(h5) + Uint32ToHexForm(h6) + Uint32ToHexForm(h7);
}

std::string HashSha2(const std::string& str)
{
    return HashSha2(str.c_str(), str.length());
}


int main()
{
    std::cout << HashSha2("`1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>? And some additional text to more changes and tests") << std::endl;
}

// b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
// b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9