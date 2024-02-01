

#ifndef COMMON_H
#define COMMON_H

typedef unsigned char Byte;

#ifdef COMMON_API
#define COMMON_API __declspec(dllexport)
#else
#define COMMON_API __declspec(dllimport)
#endif

int COMMON_API ConvertBlockOfLength(Byte* pLabel, Byte* pByte, int nByteLen, Byte* pOut);
void XorFunc(Byte* pArr1, Byte* pArr2, Byte* pOut);
int COMMON_API Hex2Asc(Byte* pDest, Byte* pSrc, int nSrcLen);
int COMMON_API Asc2Hex(Byte* pDest, Byte* pSrc, int nSrcLen);

#endif