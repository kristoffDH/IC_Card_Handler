

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ConvertBlockOfLength(Byte* pLabel, Byte* pByte, int nByteLen, Byte* pOut)
{
	Byte pBlock[2048];
	int nBlockLen = 0;
	unsigned short nBlockSize = 16;
	int idx = 0;

	memset(pBlock, 0x00, sizeof(pBlock));

	nBlockLen += sprintf((char*)pBlock + nBlockLen, "[%s]", pLabel);

	for (idx = 0; idx < nByteLen; idx++, pByte++) {
		if (idx % nBlockSize == 0)
		{
			nBlockLen += sprintf((char*)pBlock + nBlockLen, "\r\n%04x : ", idx);
		}

		nBlockLen += sprintf((char*)pBlock + nBlockLen, "%02x ", *pByte);
	}

	nBlockLen += sprintf((char*)pBlock + nBlockLen, "\r\n\r\n");

	memcpy(pOut, pBlock, nBlockLen);

	return nBlockLen;
}

void XorFunc(Byte* pArr1, Byte* pArr2, Byte* pOut)
{
	unsigned short blockSize = 16;
	int idx = 0;

	for (idx = 0; idx < blockSize; idx++)
	{
		pOut[idx] = pArr1[idx] ^ pArr2[idx];
	}
}

int Hex2Asc(Byte* Dest, Byte* Src, int SrcLen)
{
	int i;

	for (i = 0; i < SrcLen; i++)
	{
		sprintf((char*)Dest + (i * 2), "%02X", Src[i]);
	}

	Dest[i * 2] = 0;

	return SrcLen * 2;
}

int Asc2Hex(Byte* Dest, Byte* Src, int SrcLen)
{
	int i;
	for (i = 0; i < SrcLen / 2; i++)
	{
		sscanf((char*)Src + i * 2, "%02X", (Byte*)&Dest[i]);
	}

	return SrcLen / 2;
}