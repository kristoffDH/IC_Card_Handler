

#ifndef IC_CARD_FUNC_H
#define IC_CARD_FUNC_H

typedef unsigned char Byte;

#ifdef IC_CARD_FUNC_API
#define IC_CARD_FUNC_API __declspec(dllexport)
#else
#define IC_CARD_FUNC_API __declspec(dllimport)
#endif

int IC_CARD_FUNC_API Select(Byte* pFCI, Byte* pRsltCode);
int IC_CARD_FUNC_API GetCheckHash(Byte* pIcno, Byte* pCheckHash, Byte* pRsltCode);
int IC_CARD_FUNC_API GetIcno(Byte* pIcno, Byte* pRsltCode);
int IC_CARD_FUNC_API PinChallenge(Byte* pInitPin, Byte* pPin, Byte* pSRN, Byte* pPinTK, Byte* pRsltCode);
int IC_CARD_FUNC_API UnblockPinChallenge(Byte* pSRN, Byte* pCRN, Byte* pCCryptogram, Byte* pRsltCode);
int IC_CARD_FUNC_API UnblockPin(Byte* pNewPin, Byte* pCRN ,Byte* pPinTK, Byte* pSCryptogram, Byte* pRsltCode);
int IC_CARD_FUNC_API AuthenticationICCard(
	Byte* pPin, Byte* pPinTK, Byte* pTSKEY, Byte* pSRN, 
	Byte* pSAC, Byte* pEncCRN, Byte* pICAC, Byte* pRsltCode);

int IC_CARD_FUNC_API TerminationChallenge(Byte* pSRN, Byte* pCRN, Byte* pRsltCode);
int IC_CARD_FUNC_API TerminationICCard(Byte* pTSKEY, Byte* pTAC ,Byte* pRsltCode);

int IC_CARD_FUNC_API PutPerSamTEK(Byte* pEncTEK, Byte* pKCV, Byte* pResKCV,  Byte* pRsltCode);
int IC_CARD_FUNC_API AddPerSamTK(Byte* nKvn, Byte* pEncTK, Byte* pKCV, Byte* pRsltCode);
int IC_CARD_FUNC_API GetPerSamKVN(Byte* pKvnList, Byte* pRsltCode);

void IC_CARD_FUNC_API GetErrString(int errCode, Byte* errStr);

void TestICCardFunc(Byte* output);

#endif