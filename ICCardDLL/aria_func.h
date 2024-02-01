
#ifndef ARIA_FUNC_H
#define ARIA_FUNC_H

typedef unsigned char Byte;

void DL(Byte* i, Byte* o);
void RotXOR(Byte* s, int n, Byte* t);
int EncKeySetup(Byte* pKey, Byte* pRK, int nKeyBits);
int DecKeySetup(Byte* pKey, Byte* pRK, int nKeyBits);
void Crypt(Byte* pIn, int nBlockSize, Byte* pRK, Byte* pOut);
int EncryptCBC(Byte* pPlainText, int nPlainTextLen, Byte* pIV, Byte* pKey, int nKeyLen, Byte* pEncText, int* nEncTextLen);
int DecryptCBC(Byte* pEncText, int nEncTextLen, Byte* pIV, Byte* pKey, int nKeyLen, Byte* pPlainText, int* nPlainTextLen);

int AriaTest(Byte* pOutput);

#endif