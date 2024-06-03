#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>
#include <bitset>

// Define the block size for working with files
// Must be multiple 64
#define CHUNK_SIZE 4096

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

/**
    \brief A function for rotating a number
    
    The rotation of a number is equivalent to a cyclic shift of that number

    \param [in] digitToRotate the number to be rotated
    \param [in] rotateLen The number to rotate by

    \example Lets rotate 1234 number by 3
    1234 = 0b00000000000000000000010011010010
    RightRotate(1234) = 0b01000000000000000000000010011010

    \return new rotated digit
*/
uint32_t RightRotate(const uint32_t& digitToRotate, const uint32_t& rotateLen) noexcept
{
    return (digitToRotate >> rotateLen) | (digitToRotate << (sizeof(uint32_t) * 8 - rotateLen));
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

    \param [in] data a pointer to the char, starting for which you need to find the padding
    \param [in] arrayLen the number of elements in the data arr
    \param [in] dataLen the length of the source data
    \param [out] destination a pointer to the char in which padding should be written

    \return returns the length of the padding. 64 if the length of the source data was less than 56, otherwise it will return 128
*/
int DataPaddingSha2(const char* data, const std::size_t& dataLen, const std::size_t& sourceLen, char* destination) noexcept
{
    // Variable to store padding length
    int res;

    // Copy bytes from data to destination
    memcpy(destination, data, dataLen);
    
    // Set first padding bit to 1
    destination[dataLen] = 0b10000000;

    // Data length in bits
    std::uint64_t bitsLength = sourceLen * 8;

    // Check if padding have to be 128 bits
    if (dataLen < 56)
        res = 64;
    else
        res = 128;

    // Handle last 8 bytes in padding
    int i = 0;
    for (; i < 8; ++i)
    {
        // Set 63 - i or 127 - i byte in padding value of right 8 bits from bits length
        destination[res - 1 - i] = bitsLength & 0b11111111;

        // Move 8 right bits from bits length
        bitsLength >>= 8;

        // If bits length equals 0 then break
        if (bitsLength == 0) break;
    }

    // Set 0 byte to all unfilled positions
    memset(destination + dataLen + 1, 0, res - dataLen - i - 2);

    return res;
}

/**
    \brief Sha2 hashing step
    
    The function calculates the sha2 hash sum for a 64 byte block of data

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] offset a shift to indicate the beginning of the data block for which the hash is to be calculated
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
    \param [in, out] h5 internal state variable 5
    \param [in, out] h6 internal state variable 6
    \param [in, out] h7 internal state variable 7
*/
void Sha2Step(const char* data, const std::size_t& offset, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4, std::uint32_t& h5, std::uint32_t& h6, std::uint32_t& h7) noexcept
{
    // Words array
    std::uint32_t words[64] = {0};

    // Join 4 chars from data into 16 uint32_t numbers and save it to words array
    for (int i = 0; i < 64; i += 4)
        words[i >> 2] = (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + offset])) << 24) | 
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 1 + offset])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 2 + offset])) << 8) | 
            static_cast<std::uint32_t>(static_cast<unsigned char>(data[i + 3 + offset]));

    // Fill last 48 uint32_t numbers
    for (int i = 16; i < 64; ++i)
        words[i] = words[i - 16] + (RightRotate(words[i - 15], 7) ^ RightRotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] + (RightRotate(words[i - 2], 17) ^ RightRotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // Temporary variables
    std::uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    // 64 rounds to calculate hash for data block
    std::uint32_t temp1, temp2;
    for (int i = 0; i < 64; ++i)
    {
        temp1 = h + (RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25)) + ((e & f) ^ ((~e) & g)) + K[i] + words[i];
        temp2 = (RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    // Add temporary variables to hash
    h0 += a, h1 += b, h2 += c, h3 += d, h4 += e, h5 += f, h6 += g, h7 += h;
}

/**
    \brief A function for calculating the hash sum using the sha2 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
    \param [in, out] h5 internal state variable 5
    \param [in, out] h6 internal state variable 6
    \param [in, out] h7 internal state variable 7
*/
void Sha2(const char* data, const std::size_t& dataLen, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4, std::uint32_t& h5, std::uint32_t& h6, std::uint32_t& h7)
{
    // Handle 64 byte chunks
    for (std::size_t i = 0; i < dataLen >> 6; ++i)
        Sha2Step(data, i << 6, h0, h1, h2, h3, h4, h5, h6, h7);

    // Padding source data
    char padding[128];
    int paddingLen = DataPaddingSha2(data + (dataLen & ~0b00111111), dataLen & 0b00111111, dataLen, padding);

    // Calculate hash for padded data
    Sha2Step(padding, 0, h0, h1, h2, h3, h4, h5, h6, h7);

    // If padding length is 128 then calculate hash for last block
    if (paddingLen == 128)
        Sha2Step(padding, 64, h0, h1, h2, h3, h4, h5, h6, h7);
}

/**
    \brief A function for calculating the file hash sum using the sha2 algorithm

    \param [in] file ifstream object with a file to calculate the hash for
    \param [in, out] h0 internal state variable 0
    \param [in, out] h1 internal state variable 1
    \param [in, out] h2 internal state variable 2
    \param [in, out] h3 internal state variable 3
    \param [in, out] h4 internal state variable 4
    \param [in, out] h5 internal state variable 5
    \param [in, out] h6 internal state variable 6
    \param [in, out] h7 internal state variable 7
*/
void FileSha2(std::ifstream& file, std::uint32_t& h0, std::uint32_t& h1, std::uint32_t& h2, std::uint32_t& h3, std::uint32_t& h4, std::uint32_t& h5, std::uint32_t& h6, std::uint32_t& h7)
{
    // Save file size
    uint64_t fileSize = file.tellg();
    file.seekg(0);

    // Arrays to read 4kb from file and to save 4 kb to file
    char fileDataChunk[CHUNK_SIZE];

    // Counter for file reading
    std::size_t counter = 0;

    // Checking whether the file is larger than the size of the file processing chunks
    if (fileSize > CHUNK_SIZE)
    {
        // Processing the part of the file that is a multiple of the chunk size
        for(; counter < fileSize - CHUNK_SIZE; counter += CHUNK_SIZE)
        {
            // Read chunk from input file
            file.read(fileDataChunk, CHUNK_SIZE);

            // Calculate hash steps
            for (std::size_t i = 0; i < CHUNK_SIZE; i += 64)
                Sha2Step(fileDataChunk, i, h0, h1, h2, h3, h4, h5, h6, h7);
        }
    }

    // Calculating the remaining bytes in the file
    counter = fileSize - counter;

    // Read last bytes from input file
    file.read(fileDataChunk, counter);

    // Calculate hash for last bytes
    for (uint64_t i = 0; i < counter / 64; ++i)
        Sha2Step(fileDataChunk, i * 64, h0, h1, h2, h3, h4, h5, h6, h7);

    // Padding source file
    // Move fileDataChunk ptr to last position multiply by 64
    char padding[128];
    int paddingLen = DataPaddingSha2(fileDataChunk + (counter & ~0b00111111), counter & 0b00111111, fileSize, padding);

    // Calculate hash for padded data
    Sha2Step(padding, 0, h0, h1, h2, h3, h4, h5, h6, h7);

    // If padding length is 128 then calculate hash for last block
    if (paddingLen == 128)
        Sha2Step(padding, 64, h0, h1, h2, h3, h4, h5, h6, h7);
}

/**
    \brief A function for calculating the hash sum using the sha256 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] dataLen data array length

    \return a string with a sha2 hash sum
*/
std::string Sha256(const char* data, const std::size_t& dataLen) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Calculate hash
    Sha2(data, dataLen, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4) + Uint32ToHexForm(h5) + Uint32ToHexForm(h6) + Uint32ToHexForm(h7);
}

/**
    \brief A function for calculating the hash sum using the sha256 algorithm

    \param [in] str the string to calculate the hash for

    \return a string with a sha2 hash sum
*/
std::string Sha256(const std::string& str) noexcept
{
    return Sha256(str.c_str(), str.length());
}

/**
    \brief A function for calculating the file hash sum using the sha256 algorithm

    \param [in] fileName the string with file name to calculate hash for

    \return a string with a sha2 hash sum
*/
std::string FileSha256(const std::string& fileName) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    // Open file
    std::ifstream file(fileName, std::ios_base::binary | std::ios_base::ate);
    if (!file.is_open()) {std::cerr << "Can not open file: " << fileName << std::endl; return "";}

    // Calculate hash for file
    FileSha2(file, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4) + Uint32ToHexForm(h5) + Uint32ToHexForm(h6) + Uint32ToHexForm(h7);
}

/**
    \brief A function for calculating the hash sum using the sha224 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] dataLen data array length

    \return a string with a sha2 hash sum
*/
std::string Sha224(const char* data, const std::size_t& dataLen) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939, h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;

    // Calculate hash
    Sha2(data, dataLen, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4) + Uint32ToHexForm(h5) + Uint32ToHexForm(h6);
}

/**
    \brief A function for calculating the hash sum using the sha224 algorithm

    \param [in] str the string to calculate the hash for

    \return a string with a sha2 hash sum
*/
std::string Sha224(const std::string& str) noexcept
{
    return Sha224(str.c_str(), str.length());
}

/**
    \brief A function for calculating the file hash sum using the sha224 algorithm

    \param [in] fileName the string with file name to calculate hash for

    \return a string with a sha2 hash sum
*/
std::string FileSha224(const std::string& fileName) noexcept
{
    // Begin hash values
    std::uint32_t h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939, h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;

    // Open file
    std::ifstream file(fileName, std::ios_base::binary | std::ios_base::ate);
    if (!file.is_open()) {std::cerr << "Can not open file: " << fileName << std::endl; return "";}

    // Calculate hash for file
    FileSha2(file, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint32ToHexForm(h0) + Uint32ToHexForm(h1) + Uint32ToHexForm(h2) + Uint32ToHexForm(h3) + Uint32ToHexForm(h4) + Uint32ToHexForm(h5) + Uint32ToHexForm(h6);
}

int main()
{
    std::cout << Sha256("`1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>? And some additional text to more changes and tests") << std::endl;

    std::cout << FileSha256("Sha2.cpp") << std::endl;

    std::cout << Sha224("`1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>? And some additional text to more changes and tests") << std::endl;

    std::cout << FileSha224("Sha2.cpp") << std::endl;
}