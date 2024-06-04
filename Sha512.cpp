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

/// \brief Sha2 512 constants
const std::uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/**
    \brief A function for rotating a number
    
    The rotation of a number is equivalent to a cyclic shift of that number

    \param [in] digitToRotate the number to be rotated
    \param [in] rotateLen The number to rotate by

    \example Lets rotate 1234 number by 3  
    1234 = 0b0000000000000000000000000000000000000000000000000000010011010010  
    RightRotate(1234) = 0b0100000000000000000000000000000000000000000000000000000010011010  

    \return new rotated digit
*/
uint64_t RightRotate(const uint64_t& digitToRotate, const uint64_t& rotateLen) noexcept
{
    return (digitToRotate >> rotateLen) | (digitToRotate << (sizeof(uint64_t) * 8 - rotateLen));
}

/// \brief Convert uint64 to string with hex form of this number
/// \param [in] a uint64 number to convert
/// \return hex represenation of a
std::string Uint64ToHexForm(std::uint64_t a) noexcept
{
    std::string res(16, 0);
    
    for (int i = 15; i > -1; i -= 2)
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
    \brief Function for obtaining padding for the sha512 algorithm

    \param [in] data a pointer to the char, starting for which you need to find the padding. The length of the data must be less than or equal to 128
    \param [in] arrayLen the number of elements in the data arr
    \param [in] dataLen the length of the source data
    \param [out] destination a pointer to the char in which padding should be written. the length of the destination must be 128

    \return returns the length of the padding. 128 if the length of the source data was less than 112, otherwise it will return 256
*/
int DataPaddingSha512(const char* data, const std::size_t& dataLen, const std::size_t& sourceLen, char* destination) noexcept
{
    // Variable to store padding length
    int res;

    // Copy bytes from data to destination
    memcpy(destination, data, dataLen);
    
    // Set first padding bit to 1
    destination[dataLen] = 0b10000000;

    // Data length in bits
    std::uint64_t bitsLength = sourceLen * 8;

    // Check if padding have to be 256 bits
    if (dataLen < 112)
        res = 128;
    else
        res = 256;

    // Handle last 16 bytes in padding
    int i = 0;
    for (; i < 16; ++i)
    {
        // Set 127 - i or 255 - i byte in padding value of right 8 bits from bits length
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
    \brief Sha512 hashing step
    
    The function calculates the sha512 hash sum for a 128 byte block of data

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
void Sha512Step(const char* data, const std::size_t& offset, std::uint64_t& h0, std::uint64_t& h1, std::uint64_t& h2, std::uint64_t& h3, std::uint64_t& h4, std::uint64_t& h5, std::uint64_t& h6, std::uint64_t& h7) noexcept
{
    // Words array
    std::uint64_t words[80];

    // Join 8 chars from data into 16 uint64_t numbers and save it to words array
    for (int i = 0; i < 128; i += 8)
        words[i >> 3] = (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + offset])) << 56) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 1 + offset])) << 48) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 2 +offset])) << 40) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 3 + offset])) << 32) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 4 + offset])) << 24) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 5 + offset])) << 16) |
            (static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 6 + offset])) << 8) |
            static_cast<std::uint64_t>(static_cast<unsigned char>(data[i + 7 + offset]));

    // Fill last 64 uint64_t numbers
    for (int i = 16; i < 80; ++i)
        words[i] = words[i - 16] + (RightRotate(words[i - 15], 1) ^ RightRotate(words[i - 15], 8) ^ (words[i - 15] >> 7)) +
            words[i - 7] + (RightRotate(words[i - 2], 19) ^ RightRotate(words[i - 2], 61) ^ (words[i - 2] >> 6));

    // Temporary variables
    std::uint64_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    // 80 rounds to calculate hash for data block
    std::uint64_t temp1, temp2;
    for (int i = 0; i < 80; ++i)
    {
        temp1 = h + (RightRotate(e, 14) ^ RightRotate(e, 18) ^ RightRotate(e, 41)) + ((e & f) ^ ((~e) & g)) + K[i] + words[i];
        temp2 = (RightRotate(a, 28) ^ RightRotate(a, 34) ^ RightRotate(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    // Add temporary variables to hash
    h0 += a, h1 += b, h2 += c, h3 += d, h4 += e, h5 += f, h6 += g, h7 += h;
}

/**
    \brief A function for calculating the hash sum using the sha512 algorithm

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
void HashSha512(const char* data, const std::size_t& dataLen, std::uint64_t& h0, std::uint64_t& h1, std::uint64_t& h2, std::uint64_t& h3, std::uint64_t& h4, std::uint64_t& h5, std::uint64_t& h6, std::uint64_t& h7)
{
    // Handle 128 byte chunks
    for (std::size_t i = 0; i < dataLen >> 7; ++i)
        Sha512Step(data, i << 7, h0, h1, h2, h3, h4, h5, h6, h7);

    // Padding source data
    char padding[256];
    int paddingLen = DataPaddingSha512(data + (dataLen & ~0b01111111), dataLen & 0b01111111, dataLen, padding);

    // Calculate hash for padded data
    Sha512Step(padding, 0, h0, h1, h2, h3, h4, h5, h6, h7);

    // If padding length is 256 then calculate hash for last block
    if (paddingLen == 256)
        Sha512Step(padding, 128, h0, h1, h2, h3, h4, h5, h6, h7);
}

/**
    \brief A function for calculating the file hash sum using the sha512 algorithm

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
void HashFileSha512(std::ifstream& file, std::uint64_t& h0, std::uint64_t& h1, std::uint64_t& h2, std::uint64_t& h3, std::uint64_t& h4, std::uint64_t& h5, std::uint64_t& h6, std::uint64_t& h7)
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
            for (std::size_t i = 0; i < CHUNK_SIZE; i += 128)
                Sha512Step(fileDataChunk, i, h0, h1, h2, h3, h4, h5, h6, h7);
        }
    }

    // Calculating the remaining bytes in the file
    counter = fileSize - counter;

    // Read last bytes from input file
    file.read(fileDataChunk, counter);

    // Calculate hash for last bytes
    for (uint64_t i = 0; i < counter >> 7; ++i)
        Sha512Step(fileDataChunk, i << 7, h0, h1, h2, h3, h4, h5, h6, h7);

    // Padding source file
    // Move fileDataChunk ptr to last position multiply by 128
    char padding[256];
    int paddingLen = DataPaddingSha512(fileDataChunk + (counter & ~0b01111111), counter & 0b01111111, fileSize, padding);

    // Calculate hash for padded data
    Sha512Step(padding, 0, h0, h1, h2, h3, h4, h5, h6, h7);

    // If padding length is 256 then calculate hash for last block
    if (paddingLen == 256)
        Sha512Step(padding, 128, h0, h1, h2, h3, h4, h5, h6, h7);
}

/**
    \brief A function for calculating the hash sum using the sha512 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] dataLen data array length

    \return a string with a sha512 hash sum
*/
std::string Sha512(const char* data, const std::size_t& dataLen) noexcept
{
    // Begin hash values
    std::uint64_t h0 = 0x6a09e667f3bcc908, h1 = 0xbb67ae8584caa73b, h2 = 0x3c6ef372fe94f82b, h3 = 0xa54ff53a5f1d36f1, h4 = 0x510e527fade682d1, h5 = 0x9b05688c2b3e6c1f, h6 = 0x1f83d9abfb41bd6b, h7 = 0x5be0cd19137e2179;

    // Calculate hash
    HashSha512(data, dataLen, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint64ToHexForm(h0) + Uint64ToHexForm(h1) + Uint64ToHexForm(h2) + Uint64ToHexForm(h3) + Uint64ToHexForm(h4) + Uint64ToHexForm(h5) + Uint64ToHexForm(h6) + Uint64ToHexForm(h7);
}

/**
    \brief A function for calculating the hash sum using the sha512 algorithm

    \param [in] str the string to calculate the hash for

    \return a string with a sha512 hash sum
*/
std::string Sha512(const std::string& str) noexcept
{
    return Sha512(str.c_str(), str.length());
}

/**
    \brief A function for calculating the file hash sum using the sha512 algorithm

    \param [in] fileName the string with file name to calculate hash for

    \return a string with a sha512 hash sum
*/
std::string FileSha512(const std::string& fileName) noexcept
{
    // Begin hash values
    std::uint64_t h0 = 0x6a09e667f3bcc908, h1 = 0xbb67ae8584caa73b, h2 = 0x3c6ef372fe94f82b, h3 = 0xa54ff53a5f1d36f1, h4 = 0x510e527fade682d1, h5 = 0x9b05688c2b3e6c1f, h6 = 0x1f83d9abfb41bd6b, h7 = 0x5be0cd19137e2179;

    // Open file
    std::ifstream file(fileName, std::ios_base::binary | std::ios_base::ate);
    if (!file.is_open()) {std::cerr << "Can not open file: " << fileName << std::endl; return "";}

    // Calculate hash for file
    HashFileSha512(file, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint64ToHexForm(h0) + Uint64ToHexForm(h1) + Uint64ToHexForm(h2) + Uint64ToHexForm(h3) + Uint64ToHexForm(h4) + Uint64ToHexForm(h5) + Uint64ToHexForm(h6) + Uint64ToHexForm(h7);
}

/**
    \brief A function for calculating the hash sum using the sha384 algorithm

    \param [in] data a pointer to the array to calculate the hash for
    \param [in] dataLen data array length

    \return a string with a sha384 hash sum
*/
std::string Sha384(const char* data, const std::size_t& dataLen) noexcept
{
    // Begin hash values
    std::uint64_t h0 = 0xcbbb9d5dc1059ed8, h1 = 0x629a292a367cd507, h2 = 0x9159015a3070dd17, h3 = 0x152fecd8f70e5939, h4 = 0x67332667ffc00b31, h5 = 0x8eb44a8768581511, h6 = 0xdb0c2e0d64f98fa7, h7 = 0x47b5481dbefa4fa4;

    // Calculate hash
    HashSha512(data, dataLen, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint64ToHexForm(h0) + Uint64ToHexForm(h1) + Uint64ToHexForm(h2) + Uint64ToHexForm(h3) + Uint64ToHexForm(h4) + Uint64ToHexForm(h5);
}

/**
    \brief A function for calculating the hash sum using the sha384 algorithm

    \param [in] str the string to calculate the hash for

    \return a string with a sha384 hash sum
*/
std::string Sha384(const std::string& str) noexcept
{
    return Sha384(str.c_str(), str.length());
}

/**
    \brief A function for calculating the file hash sum using the sha384 algorithm

    \param [in] fileName the string with file name to calculate hash for

    \return a string with a sha384 hash sum
*/
std::string FileSha384(const std::string& fileName) noexcept
{
    // Begin hash values
    std::uint64_t h0 = 0xcbbb9d5dc1059ed8, h1 = 0x629a292a367cd507, h2 = 0x9159015a3070dd17, h3 = 0x152fecd8f70e5939, h4 = 0x67332667ffc00b31, h5 = 0x8eb44a8768581511, h6 = 0xdb0c2e0d64f98fa7, h7 = 0x47b5481dbefa4fa4;

    // Open file
    std::ifstream file(fileName, std::ios_base::binary | std::ios_base::ate);
    if (!file.is_open()) {std::cerr << "Can not open file: " << fileName << std::endl; return "";}

    // Calculate hash for file
    HashFileSha512(file, h0, h1, h2, h3, h4, h5, h6, h7);

    // Return calculated hash
    return Uint64ToHexForm(h0) + Uint64ToHexForm(h1) + Uint64ToHexForm(h2) + Uint64ToHexForm(h3) + Uint64ToHexForm(h4) + Uint64ToHexForm(h5);
}

int main()
{
    std::cout << Sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") << std::endl;

    std::cout << FileSha512("tex") << std::endl;

    std::cout << Sha384("affa") << std::endl;

    std::cout << FileSha384("tex") << std::endl;
}