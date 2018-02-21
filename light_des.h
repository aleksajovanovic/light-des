#ifndef LIGHT_DES_H
#define LIGHT_DES_H

#include <stdlib.h>
#include <stdio.h>

#define bit 1
#define HALF_NIBBLE 2
#define NIBBLE 4
#define BYTE 8
#define BLOCK 12
#define HALF_BLOCK 6
#define BLOCK_SET_LOW 63
#define KEY_SHIFTS 9
#define KEY_SET_HIGH 511
/*
typedef struct Block {
    uint16_t block;
} Block;*/

typedef struct BlockList {
    size_t length;
    uint16_t blockList[];
} BlockList;

typedef struct Stream {
    unsigned char *contents;
    size_t length;
} Stream;

Stream *readInput();
Stream *readFile(FILE *file);
void EcbDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key);
void CbcDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key);
void CtrDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key);
BlockList *assembleBlockList(Stream *stream, long numBlocks);
uint16_t assemblePrevBlock(Stream *stream, int i);
uint16_t assembleNextBlock(Stream *stream, int i);
uint16_t assembleLastBlock(Stream *stream, int i);
void printBlock(uint16_t block);
void lightDES(Stream *stream, char *mode, char *cipher, int rounds, uint16_t key);
unsigned char generateRoundKey(uint16_t key, int roundNum);
unsigned char twosPow(char exponent);
unsigned char expand(unsigned char right);
unsigned char s1Box(unsigned char right);
unsigned char s2Box(unsigned char right);
unsigned char *readStringAsHex(unsigned char *input, int length);
void printBlockList(BlockList *blockList, long numBlocks);

#endif