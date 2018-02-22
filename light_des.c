#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "light_des.h"

int main(int argc, char *argv[])
{
    if(argc != 7) {
        printf("Usage: light-des [--mode] [--enc/--dec] [--hex/--file] [int rounds] [decimal key] [plaintext/file name]\n");
        exit(1);
    }
    
    char *mode = argv[1];
    char *cipher = argv[2];
    char *inputType = argv[3];
    unsigned char *input;

    int rounds;
    unsigned int _key;
    FILE *file;
    Stream *stream = malloc(sizeof(Stream));

    int roundIndex = 4;
    int keyIndex = 5;
    int inputIndex = 6;

    if(sscanf(argv[roundIndex], "%i", &rounds) != 1) {
        printf("the number of rounds must be an integer\n");
        exit(1);
    }
    
    if(sscanf(argv[keyIndex], "%u", &_key) != 1) {
        printf("the key must be an integer between [0-512)\n");
        exit(1);
    }

    int length = strlen(argv[inputIndex]);
    input = malloc(length);
    memcpy(input, argv[inputIndex], length);
    input[length] = '\0';

    if((strcmp(inputType, "--hex") == 0)) {
        stream->contents = readStringAsHex(input, length);
        stream->length = length/2; 
    }
    else {
        stream->contents = input;
        stream->length = length;
    }

    if(_key > 511) {
        printf("the key must be an integer between [0-512)\n");
        exit(1);
    }

    uint16_t key = (uint16_t) _key;

    if((strcmp(mode, "--ECB") != 0) && (strcmp(mode, "--CTR") != 0) && (strcmp(mode, "--CBC") != 0)) {
        printf("Please choose a correct mode [--ECB/--CTR/--CBC]\n");
        exit(1);  
    }

    if((strcmp(cipher, "--enc") != 0) && (strcmp(cipher, "--dec") != 0)) {
        printf("Please choose if you are encrypting or decrypting [--enc/--dec]\n");
        exit(1);  
    }
    
    file = fopen((char *)stream->contents, "rb");

    if(file) {
        free(stream);
        stream = readFile(file);
    }

    if(strcmp(mode, "--ECB") == 0) {
        EcbDES(stream, mode, cipher, rounds, key);
    }

    if(strcmp(mode, "--CBC") == 0) {
        CbcDES(stream, mode, cipher, rounds, key);
    }
}

void printBlock(uint16_t block)
{
    for(int i = 0; i < 12; i++) {
        printf("%d", ((block << i) & 0x800) != 0);
    }
}

unsigned char *readStringAsHex(unsigned char *input, int length)
{
    int index = 0;
    unsigned char hex = 0;
    unsigned long temp = 0;
    unsigned char *hexValues = malloc(sizeof(length / 2));

    for(int i = 0; i < length; i+=2) {
        char ch1 = 0;
        ch1 |= input[i];
        char ch2 = 0;
        ch2 |= input[i+1];
        char byte[3] = {ch1, ch2, '\0'};
        temp = strtoul(byte, 0, 16);
        hex = (unsigned char) temp;
        hexValues[index] = hex;
        hex = 0;

        index++;
    }
    hexValues[length/2] = '\0';
    return hexValues;
}

// dynamic user command line input for file name or raw input
Stream *readInput()
{
    int c;
    size_t buffer = 100;
    size_t inputLen = 0;
    unsigned char *input = malloc(sizeof(unsigned char));
    Stream *stream = malloc(sizeof(Stream));

    while((c = fgetc(stdin)) != '\n') {
        input[inputLen] = c;
        if(++inputLen == buffer)
            input = realloc(input, (buffer *= 2) * sizeof(char));

        }
        
    input = realloc(input, (inputLen + 1) * sizeof(char));
    input[inputLen] = '\0'; 

    stream->contents = input;
    stream->length = inputLen;

    return stream;
}

// dynamic size of file contents
Stream *readFile(FILE *file)
{
    Stream *stream = (Stream *) malloc(sizeof(Stream));

    if(fseek(file, 0L, SEEK_END) != 0) {
        printf("SEEK_END not found");
        exit(1);
    }

    long bufferSize = ftell(file);
    
    if(bufferSize == -1) {
        printf("something's wrong");
        exit(1);
    }

    unsigned char *contents = malloc(sizeof(unsigned char) * (bufferSize + 1));

    if(fseek(file, 0L, SEEK_SET) != 0) {
        printf("SEEK_SET not found");
        exit(1);
    }

    size_t len = fread(contents, sizeof(unsigned char), bufferSize, file);

    if(ferror(file) != 0) {
        printf("error reading file");
        exit(1);
    }

    fclose(file);
    contents[len] = '\0';
    stream->contents = contents;
    stream->length = len;

    return stream;
}

void printBlockList(BlockList *blockList, long numBytes)
{
    for(int i = 0; i < blockList->length; i++) {
        if(i == (blockList->length - 1)) {
            long r = (numBytes * 8) % 12; 
            
            if(r == 4l) {
                printf("%x", blockList->blockList[i] & 0xf);
                return;
            }

            if(r == 8l) {
                printf("%02x", blockList->blockList[i] & 0xff);
                return;
            }
        }

        printf("%03x", blockList->blockList[i] & 0xfff);
    }
}

void EcbDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key)
{
    long numberBits = stream->length * BYTE;
    long numBlocks = 0;

    if(numberBits % 12 == 0)
        numBlocks = numberBits / 12;
    else
        numBlocks = (numberBits / 12) + 1;

    BlockList *blockList = assembleBlockList(stream, numBlocks);
  
    for(int i = 0; i < blockList->length; i++) {
        uint16_t block = blockList->blockList[i];

        for(int j = 1; j <= rounds; j++) {
            int roundNum = (strcmp(cipher, "--dec") == 0) ? (rounds - j + 1) : j;
            unsigned char roundKey = generateRoundKey(key, roundNum);
            unsigned char left = BLOCK_SET_LOW;
            unsigned char right = BLOCK_SET_LOW;
            unsigned char temp = 0;

            left &= (block>> 6);
            temp = left;
            right &= block;
            left = right;
            right = expand(right);
            right ^= roundKey;

            unsigned char s1Res = s1Box(right);
            unsigned char s2Res = s2Box(right);
            
            right = (s1Res << 3) | s2Res;
            right ^= temp;

            uint16_t newBlock = right;
            newBlock <<= 6;
            newBlock |= left;
            block = newBlock;
            blockList->blockList[i] = block;
        }
    }

    printBlockList(blockList, stream->length);
}

void CbcDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key)
{
    printf("\nplease enter 1 for fixed IV and 2 for nonce generated IV: ");
    int ivType;
    uint16_t iv;
    scanf("%d", &ivType);

    if(ivType == 1) {
        iv = 0xE38;
    }
    else {
        if(strcmp(cipher, "--dec") == 0) {
            printf("\nPlease provide your nonce for decryption: ");
            scanf("%hu", &iv);
            printf("\nthe nonce scanned in is %hu\n", iv);
        }
        else {
            srand(time(NULL));
            iv = rand() % (4095 + 1 - 0) + 0;
            printf("\nYour nonce for decryption is %d\n", iv);
        }
    }

    long numberBits = stream->length * BYTE;
    long numBlocks = 0;

    if(numberBits % 12 == 0)
        numBlocks = numberBits / 12;
    else
        numBlocks = (numberBits / 12) + 1;

    BlockList *blockList = assembleBlockList(stream, numBlocks);
    BlockList *oldCipher = assembleBlockList(stream, numBlocks);
  
    for(int i = 0; i < blockList->length; i++) {
        uint16_t block;
        uint16_t prevBlock;

        if(strcmp(cipher, "--dec") == 0) {
            block = blockList->blockList[i];
            if(i != 0) {
                prevBlock = oldCipher->blockList[i - 1];
            }
        }
        else {
            block = blockList->blockList[i] ^ iv;
        }
        
        for(int j = 1; j <= rounds; j++) {
            int roundNum = (strcmp(cipher, "--dec") == 0) ? (rounds - j + 1) : j;
            unsigned char roundKey = generateRoundKey(key, roundNum);
            unsigned char left = BLOCK_SET_LOW;
            unsigned char right = BLOCK_SET_LOW;
            unsigned char temp = 0;

            left &= (block >> 6);
            temp = left;
            right &= block;
            left = right;
            right = expand(right);
            right ^= roundKey;

            unsigned char s1Res = s1Box(right);
            unsigned char s2Res = s2Box(right);
            
            right = (s1Res << 3) | s2Res;
            right ^= temp;

            uint16_t newBlock = right;
            newBlock <<= 6;
            newBlock |= left;
            block = newBlock;
            blockList->blockList[i] = block;

        }

        if(strcmp(cipher, "--dec") == 0) {
            uint16_t temp = (i == 0) ? (block ^ iv) : (block ^ prevBlock);
            blockList->blockList[i] = temp;
        }
        else {
            blockList->blockList[i] = block;
            iv = block;
        }
    }

    printBlockList(blockList, stream->length);
}

unsigned char generateRoundKey(uint16_t key, int roundNum)
{
    char startIndex = (--roundNum % KEY_SHIFTS) + 1;
    unsigned char endMask = 0;
    unsigned char numBitsMask = 0;

    unsigned char newKey = (startIndex == 1) ? key >> 1 : key << (startIndex - 2);
    numBitsMask = twosPow((startIndex - 2)) - 1;
    endMask = ((startIndex - 2) > 0) ? ((key >> (KEY_SHIFTS - startIndex + 2)) & numBitsMask) : 0;

    return newKey |= endMask;
}

unsigned char twosPow(char exponent)
{
    return (exponent < 1) ? 1 : 1 << exponent;
}

unsigned char expand(unsigned char right)
{
    unsigned char expanded = right << 2;
    unsigned char mask = 0xc0;
    unsigned char temp = 0;

    //first two
    expanded &= mask;
    mask = 0x20;
    temp = right << 2;
    temp &= mask;
    temp = temp | (temp >> 2);
    temp >>= 1;
    expanded |= temp;
    //middle four
    temp = right << 2;
    mask = 0x10;
    temp &= mask;
    temp = temp | (temp << 2);
    temp >>=1;
    expanded |= temp;
    //last two
    mask = 0x3;
    temp = right & mask;
    expanded |= temp;
    
    return expanded;
}

unsigned char s1Box(unsigned char right)
{
    unsigned char leftFour = (right >> 4) & 0xf;
    unsigned char s1[2][8] = {{5, 2, 1, 6, 3, 4, 7, 0}, {1, 4, 6, 2, 0, 7, 5, 3}};
    unsigned char row = (leftFour >> 3) & 1;
    unsigned char col = leftFour & 7;

    return s1[row][col];
}

unsigned char s2Box(unsigned char right)
{
    unsigned char rightFour = right & 0xf;
    unsigned char s2[2][8] = {{4, 0, 6, 5, 7, 1, 3, 2}, {5, 3, 0, 7, 6, 2, 1, 4}};
    unsigned char row = (rightFour >> 3) & 1;
    unsigned char col = rightFour & 7;

    return s2[row][col];
}

BlockList *assembleBlockList(Stream *stream, long numBlocks)
{   
    BlockList *blockList;
    blockList = malloc(sizeof(BlockList) + (2 * numBlocks * sizeof(long)));
    blockList->length = 0;

    if(stream->length == 1) {
        uint16_t block = 0;
        uint16_t temp = 0;
        temp |= stream->contents[0];
        block = temp;
        blockList->blockList[0] = block;
        blockList->length += 1;
        return blockList;
    }

    for(int i = 1; i < stream->length; i += 3) {
        uint16_t prevBlock = 0;
        uint16_t nextBlock = 0;
        prevBlock = assemblePrevBlock(stream, i);
        nextBlock = assembleNextBlock(stream, i);
        blockList->blockList[blockList->length] = prevBlock;
        blockList->length += 1;
        blockList->blockList[blockList->length] = nextBlock;
        blockList->length += 1;

        if((i + 3) == stream->length) {
            blockList->blockList[blockList->length] = assembleLastBlock(stream, i);
            blockList->length += 1;
        }
    }

    return blockList;
}

uint16_t assemblePrevBlock(Stream *stream, int i)
{
    uint16_t prevBlock = 0;

    uint16_t full = 0;
    uint16_t half = 0xf0;

    //previous block
    full |= (uint16_t) stream->contents[i - 1];
    full <<= NIBBLE;
    half &= (uint16_t) stream->contents[i];
    half >>= NIBBLE;
    full |= half;

    prevBlock = full;
    
    return prevBlock;
}

uint16_t assembleNextBlock(Stream *stream, int i)
{
    uint16_t nextBlock = 0;

    uint16_t full = 0;
    uint16_t half = 0xf;

    //next block
    half &= (uint16_t) stream->contents[i];

    if((i + 1) >= stream->length) {
        nextBlock = half;
        return nextBlock;
    }

    half <<= BYTE;
    full |= (uint16_t) stream->contents[i + 1];
    half |= full;

    nextBlock = half;
    
    return nextBlock;
}

uint16_t assembleLastBlock(Stream *stream, int i)
{
    uint16_t full = 0;
    full |= (uint16_t) stream->contents[i + 2];

    uint16_t block = 0;
    block = full;

    return block;
}
