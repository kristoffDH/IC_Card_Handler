
#ifndef SCARD_READER_FUNC_H
#define SCARD_READER_FUNC_H


typedef unsigned char Byte;

long SCardOpen();
void SCardClose();
long SCardReset();
long SCardTransmitAPDU(Byte* pApdu, int nApduLen, Byte* pResponse, int* nResponseLen, Byte* pStatusCode);
int SCardGetErrCode(long lErrCode);

int SCardTest(Byte* pOutput);

#endif