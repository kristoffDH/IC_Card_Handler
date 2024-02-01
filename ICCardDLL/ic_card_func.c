

#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "common.h"
#include "ic_card_func.h"
#include "aria_func.h"
#include "KISA_SHA256.h"
#include "scard_reader_func.h"

#if TRUE
#define IC_CARD_S_SUCCESS						0x0000
#define IC_CARD_E_INVALID_PARAM_LENGTH			0x0001
#define IC_CARD_E_OPEN_FAIL						0x0002

#define IC_CARD_E_SELECT_ERROR					0x0100
#define IC_CARD_E_GET_ICNO_ERROR				0x0101
#define IC_CARD_E_GET_CHECK_HASH_ERROR			0x0102
#define IC_CARD_E_GET_CHALLENGE_ERROR			0x0103
#define IC_CARD_E_CHANGE_PIN_FAIL				0x0104
#define IC_CARD_E_UNBLOCK_PIN_FAIL				0x0105
#define IC_CARD_E_VERIFY_PIN_FAIL				0x0106
#define IC_CARD_E_AUTHENTICATE_FIAL				0x0107
#define IC_CARD_E_LIFE_CYCLE_ERROR				0x0108
#define IC_CARD_E_PUT_KEY_ERROR					0x0109
#define IC_CARD_E_GET_DATA						0x0110
#define IC_CARD_E_ADD_KEY_ERROR					0x0111
#define IC_CARD_E_REMAINING_PIN_TRY_ERROR		0x0112
#define IC_CARD_E_GET_TERMINATION_CHALLENGE_ERROR 0x0113
#define IC_CARD_E_GET_TERMINATION_ERROR			0x0114

#define IC_CARD_E_MAKE_SEK_FAIL					0x0201
#define IC_CARD_E_MAKE_SMK_FAIL					0x0202
#define IC_CARD_E_MAKE_MAC_FAIL					0x0203
#define IC_CARD_E_MAKE_ENC_USR_PIN_FAIL			0x0204
#define IC_CARD_E_MAKE_ENC_UNBLOCK_PIN_FAIL		0x0205
#define IC_CARD_E_MAKE_ENC_PIN_FAIL				0x0206

#endif

int Select(Byte* pFCI, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };
	int nReturnCode = SCardOpen();

	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	memcpy(pFCI, pRes, nResSize);

	SCardClose();
	return IC_CARD_S_SUCCESS;
}

int GetCheckHash(Byte* pICNO, Byte* pCheckHash, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pApduGetIcnoCmd[] = { 0x00, 0xCA, 0x00, 0x00, 0x0A };
	Byte pApduGetCheckHashCmd[] = { 0x00, 0xCA, 0x00, 0xFF, 0x20 };
	
	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };
	int nReturnCode = SCardOpen();

	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// get icno
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetIcnoCmd, sizeof(pApduGetIcnoCmd), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_GET_ICNO_ERROR;
	}

	memcpy(pICNO, pRes, nResSize);

	// get data(check hash)
	memset(pRes, 0x00, sizeof(pRes));
	
	SCardTransmitAPDU(pApduGetCheckHashCmd, sizeof(pApduGetCheckHashCmd), pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_GET_CHECK_HASH_ERROR;
	}

	memcpy(pCheckHash, pRes, nResSize);

	SCardClose();

    return IC_CARD_S_SUCCESS;
}

int GetIcno(Byte* pICNO, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;
	
	Byte pApduGetData[] = { 0x00, 0xCA, 0x00, 0x00, 0x0A };

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };
	long lRsltCode = 0;
	int nReturnCode = SCardOpen();

	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// get data(check hash)
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetData, sizeof(pApduGetData), pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_GET_CHECK_HASH_ERROR;
	}

	memcpy(pICNO, pRes, nResSize);

	SCardClose();

    return IC_CARD_S_SUCCESS;
}

int PinChallenge(Byte* pInitPin,Byte* pPin, Byte* pSRN, Byte* pPinTK, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;
	
	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pApduChallenge[128] = { 0, };
	int nApduChallengeLen = 0;
	Byte pChallengeCmd[] = { 0x00, 0x84, 0x00, 0x00, 0x10 };

	Byte pCRN[32] = { 0, };
	Byte pSek[32] = { 0, };
	Byte pSmk[32] = { 0, };
	Byte pEncUsrPin[32] = { 0, };
	int nEncUsrPinLen = 0;

	Byte pChangeCmd[] = { 0x84,0x24,0x00,0x00,0x18 };
	Byte pApduChange[128] = { 0, };
	int nApduChangeLen = 0;
	Byte pMacInput[32] = { 0, };
	int nMacInputLen = 0;
	Byte pMac[8] = { 0, };

	Byte pIV[16] = { 0, };
	Byte pKD_ENC[32] = { 0, };
	Byte pKD_MAC[32] = { 0, };
	Byte pEncData[256] = { 0, };
	int nEncDataLen = 0;
	int nRv = 0;
	Byte padding = 0x80;
	Byte pInputData[256] = { 0, };
	int nInputLen = 0;
	int nMacPos = 0;

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	if (pRes[nResSize-1] != 0x03) {
		memset(pStatusCode, 0x00, 2);
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_LIFE_CYCLE_ERROR;
	}

	// Send GET Challenge APDU
	// response - CRN | STATUS CODE(2byte)
	memcpy(pApduChallenge, pChallengeCmd, sizeof(pChallengeCmd));
	nApduChallengeLen += sizeof(pChallengeCmd);
	memcpy(pApduChallenge+nApduChallengeLen, pSRN, 16);
	nApduChallengeLen += 16;

	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChallenge, nApduChallengeLen, pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		memcpy(pRsltCode, pStatusCode, 2);
		SCardClose();
		return IC_CARD_E_GET_CHALLENGE_ERROR;
	}

	memcpy(pCRN, pRes, nResSize);

	// Make SEK
	// set KD_ENC
	memset(pKD_ENC, 0x00, sizeof(pKD_ENC));
	memcpy(pKD_ENC, pCRN, 16);
	pKD_ENC[27] = 0x04;
	pKD_ENC[30] = 0x80;
	pKD_ENC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_ENC, sizeof(pKD_ENC), pIV, pPinTK, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_SEK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSek);


	// Make SMK
	// set KD_MAC
	memset(pKD_MAC, 0x00, sizeof(pKD_MAC));
	memcpy(pKD_MAC, pCRN, 16);
	pKD_MAC[27] = 0x06;
	pKD_MAC[30] = 0x80;
	pKD_MAC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_MAC, sizeof(pKD_MAC), pIV, pPinTK, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_SMK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSmk);
	

	// Make ENC USR PIN
	memcpy(pInputData, pInitPin, 8);
	nInputLen += 8;
	memcpy(pInputData + nInputLen, pPin, 4);
	nInputLen += 4;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSek, 16, pEncData, &nEncDataLen);

	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_ENC_USR_PIN_FAIL;
	}

	memcpy(pEncUsrPin, pEncData, nEncDataLen);
	nEncUsrPinLen = nEncDataLen;

	// Make MAC
	memset(pInputData, 0x00, sizeof(pInputData));
	nInputLen = 0;

	memcpy(pInputData, pChangeCmd, sizeof(pChangeCmd));
	nInputLen += sizeof(pChangeCmd);
	memcpy(pInputData + nInputLen, pEncUsrPin, nEncUsrPinLen);
	nInputLen += nEncUsrPinLen;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSmk, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_MAC_FAIL;
	}

	nMacPos = nEncDataLen - 16;

	memcpy(pMac, pEncData + nMacPos, 8);

	// Change APDU
	memcpy(pApduChange, pChangeCmd, sizeof(pChangeCmd));
	nApduChangeLen += sizeof(pChangeCmd);
	memcpy(pApduChange + nApduChangeLen, pEncUsrPin, nEncUsrPinLen);
	nApduChangeLen += nEncUsrPinLen;
	memcpy(pApduChange + nApduChangeLen, pMac, 8);
	nApduChangeLen += 8;


	// Send Change Pin APDU
	memset(pRes, 0x00, sizeof(pRes));	
	SCardTransmitAPDU(pApduChange, nApduChangeLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_CHANGE_PIN_FAIL;
	}

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int UnblockPinChallenge(Byte* pSRN, Byte* pCRN, Byte* pCCryptogram, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pApduChallenge[128] = { 0, };
	int nApduChallengeLen = 0;
	Byte pChallengeCmd[] = { 0x00, 0x84, 0x01, 0x00, 0x10 };
	int nPos = 0;
	
	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	if (pRes[nResSize-1] != 0x05) {
		memset(pStatusCode, 0x00, 2);
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_LIFE_CYCLE_ERROR;
	}

	// Send GET Challenge APDU
	// response - CRN | CCryptogram STATUS CODE(2byte)
	memcpy(pApduChallenge, pChallengeCmd, sizeof(pChallengeCmd));
	nApduChallengeLen += sizeof(pChallengeCmd);
	memcpy(pApduChallenge + nApduChallengeLen, pSRN, 16);
	nApduChallengeLen += 16;

	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChallenge, nApduChallengeLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_GET_CHALLENGE_ERROR;
	}

	memcpy(pCRN, pRes, 16);
	memcpy(pCCryptogram, pRes+16, 8);

	return IC_CARD_S_SUCCESS;
}

int UnblockPin(Byte* pNewPin, Byte* pCRN, Byte* pPinTK, Byte* pSCryptogram, Byte* pRsltCode)
{
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pSek[32] = { 0, };
	Byte pSmk[32] = { 0, };
	Byte pEncUnblockPin[32] = { 0, };
	int nEncUnblockPinLen = 0;

	Byte pUnlockPinCmd[] = { 0x84,0x2c,0x00,0x00,0x18 };
	Byte pApduUnlockPin[128] = { 0, };
	int nApduUnlockPinLen = 0;
	Byte pMacInput[32] = { 0, };
	int nMacInputLen = 0;
	Byte pMac[8] = { 0, };

	Byte pIV[16] = { 0, };
	Byte pKD_ENC[32] = { 0, };
	Byte pKD_MAC[32] = { 0, };
	Byte pEncData[256] = { 0, };
	int nEncDataLen = 0;
	int nRv = 0;
	Byte padding = 0x80;
	Byte pInputData[256] = { 0, };
	int nInputLen = 0;
	int nMacPos = 0;


	// Make SEK
	// set KD_ENC
	memset(pKD_ENC, 0x00, sizeof(pKD_ENC));
	memcpy(pKD_ENC, pCRN, 16);
	pKD_ENC[27] = 0x04;
	pKD_ENC[30] = 0x80;
	pKD_ENC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_ENC, sizeof(pKD_ENC), pIV, pPinTK, 16, pEncData, &nEncDataLen);

	if (nRv == FALSE) {
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_MAKE_SEK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSek);


	// Make SMK
	// set KD_MAC
	memset(pKD_MAC, 0x00, sizeof(pKD_MAC));
	memcpy(pKD_MAC, pCRN, 16);
	pKD_MAC[27] = 0x06;
	pKD_MAC[30] = 0x80;
	pKD_MAC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_MAC, sizeof(pKD_MAC), pIV, pPinTK, 16, pEncData, &nEncDataLen);

	if (nRv == FALSE) {
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_MAKE_SMK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSmk);

	// Make Unblock Usr Pin
	memcpy(pInputData, pSCryptogram, 8);
	nInputLen += 8;
	memcpy(pInputData + nInputLen, pNewPin, 4);
	nInputLen += 4;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSek, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		return IC_CARD_E_MAKE_ENC_UNBLOCK_PIN_FAIL;
	}

	memcpy(pEncUnblockPin, pEncData, nEncDataLen);
	nEncUnblockPinLen = nEncDataLen;


	// Make MAC
	memset(pInputData, 0x00, sizeof(pInputData));
	nInputLen = 0;

	memcpy(pInputData, pUnlockPinCmd, sizeof(pUnlockPinCmd));
	nInputLen += sizeof(pUnlockPinCmd);
	memcpy(pInputData + nInputLen, pEncUnblockPin, nEncUnblockPinLen);
	nInputLen += nEncUnblockPinLen;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSmk, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_MAC_FAIL;
	}

	nMacPos = nEncDataLen - 16;

	memcpy(pMac, pEncData + nMacPos, 8);

	// Unblock APDU
	memcpy(pApduUnlockPin, pUnlockPinCmd, sizeof(pUnlockPinCmd));
	nApduUnlockPinLen += sizeof(pUnlockPinCmd);
	memcpy(pApduUnlockPin + nApduUnlockPinLen, pEncUnblockPin, nEncUnblockPinLen);
	nApduUnlockPinLen += nEncUnblockPinLen;
	memcpy(pApduUnlockPin + nApduUnlockPinLen, pMac, 8);
	nApduUnlockPinLen += 8;

	// Send Unblock Pin APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduUnlockPin, nApduUnlockPinLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_UNBLOCK_PIN_FAIL;
	}

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int AuthenticationICCard
(
	Byte* pPin, Byte* pPinTK, Byte* pTSKEY, Byte* pSRN,
	Byte* pSAC, Byte* pEncCRN, Byte* pICAC, Byte* pRsltCode
)
{
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pApduChallenge[128] = { 0, };
	int nApduChallengeLen = 0;
	Byte pChallengeCmd[] = { 0x00, 0x84, 0x00, 0x00, 0x10 };

	Byte pApduRemaningPinTryCmd[] = { 0x00, 0xCA, 0x00, 0x03, 0x01 };

	Byte pSek[32] = { 0, };
	Byte pSmk[32] = { 0, };
	Byte pCRN[32] = { 0, };
	int nSekLen = 16;
	int nSmkLen = 16;
	Byte pEncPin[32] = { 0, };
	int nEncPinLen = 0;

	Byte pMac[32] = { 0, };
	int nMacInputLen = 0;

	Byte pVerifyCmd[] = { 0x84,0x20,0x00,0x00,0x18 };
	Byte pApduVerify[128] = { 0, };
	int nApduVerifyLen = 0;
	
	Byte pAuthenticateCmd[] = { 0x00,0x88,0x00,0x00,0x62 };
	Byte pLvTsKey = 0x40;
	Byte pLvSac = 0x20;
	Byte pApduAuthenticate[512] = { 0, };
	int nApduAuthenticateLen = 0;

	Byte pIV[16] = { 0, };
	Byte pKD_ENC[32] = { 0, };
	Byte pKD_MAC[32] = { 0, };
	Byte pEncData[256] = { 0, };
	int nEncDataLen = 0;
	int nRv = 0;
	Byte padding = 0x80;
	Byte pInputData[256] = { 0, };
	int nInputLen = 0;
	int nMacPos = 0;

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	if (pRes[nResSize-1] != 0x04) {
		memset(pStatusCode, 0x00, 2);
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_LIFE_CYCLE_ERROR;
	}

	// Send Get Data(remaining pin try)
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduRemaningPinTryCmd, sizeof(pApduRemaningPinTryCmd), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_REMAINING_PIN_TRY_ERROR;
	}

	memcpy(pApduChallenge, pChallengeCmd, sizeof(pChallengeCmd));
	nApduChallengeLen += sizeof(pChallengeCmd);
	memcpy(pApduChallenge+nApduChallengeLen, pSRN, 16);
	nApduChallengeLen += 16;

	// Send GET Challenge APDU
	// response - CRN | STATUS CODE(2byte)
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChallenge, nApduChallengeLen, pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_GET_CHALLENGE_ERROR;
	}

	memcpy(pCRN, pRes, nResSize);

	// Make SEK
	// set KD_ENC
	memset(pKD_ENC, 0x00, sizeof(pKD_ENC));
	memcpy(pKD_ENC, pCRN, 16);
	pKD_ENC[27] = 0x04;
	pKD_ENC[30] = 0x80;
	pKD_ENC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_ENC, sizeof(pKD_ENC), pIV, pPinTK, 16, pEncData, &nEncDataLen);

	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_SEK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSek);


	// Make SMK
	// set KD_MAC
	memset(pKD_MAC, 0x00, sizeof(pKD_MAC));
	memcpy(pKD_MAC, pCRN, 16);
	pKD_MAC[27] = 0x06;
	pKD_MAC[30] = 0x80;
	pKD_MAC[31] = 0x01;

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pKD_MAC, sizeof(pKD_MAC), pIV, pPinTK, 16, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_SMK_FAIL;
	}

	SHA256_Encrpyt(pEncData, nEncDataLen, pSmk);


	// Make ENC PIN
	nInputLen = 0;
	memcpy(pInputData, pPin, 4);
	nInputLen += 4;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSek, nSekLen, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_ENC_PIN_FAIL;
	}

	memcpy(pEncPin, pEncData, nEncDataLen);
	nEncPinLen = nEncDataLen;


	// Make MAC
	memset(pInputData, 0x00, sizeof(pInputData));
	nInputLen = 0;

	memcpy(pInputData, pVerifyCmd, sizeof(pVerifyCmd));
	nInputLen += sizeof(pVerifyCmd);
	memcpy(pInputData + nInputLen, pEncPin, nEncPinLen);
	nInputLen += nEncPinLen;

	if (nInputLen % 16 != 0)
	{
		memcpy(pInputData + nInputLen, &padding, 1);
		nInputLen = (nInputLen / 16) * 16 + 16;
	}

	memset(pEncData, 0x00, sizeof(pEncData));
	nRv = EncryptCBC(pInputData, nInputLen, pIV, pSmk, nSmkLen, pEncData, &nEncDataLen);
	if (nRv == FALSE) {
		SCardClose();
		return IC_CARD_E_MAKE_MAC_FAIL;
	}

	nMacPos = nEncDataLen - 16;

	memcpy(pMac, pEncData + nMacPos, 8);

	// Verify APDU
	memcpy(pApduVerify, pVerifyCmd, sizeof(pVerifyCmd));
	nApduVerifyLen += sizeof(pVerifyCmd);
	memcpy(pApduVerify + nApduVerifyLen, pEncPin, nEncPinLen);
	nApduVerifyLen += nEncPinLen;
	memcpy(pApduVerify + nApduVerifyLen, pMac, 8);
	nApduVerifyLen += 8;

	// Send Verify Pin APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduVerify, nApduVerifyLen+1, pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_VERIFY_PIN_FAIL;
	}

	// AUTHENTICATE
	memcpy(pApduAuthenticate, pAuthenticateCmd, sizeof(pAuthenticateCmd));
	nApduAuthenticateLen += sizeof(pAuthenticateCmd);
	memcpy(pApduAuthenticate + nApduAuthenticateLen, &pLvTsKey, 1);
	nApduAuthenticateLen++;
	memcpy(pApduAuthenticate + nApduAuthenticateLen, pTSKEY, 64);
	nApduAuthenticateLen += 64;
	memcpy(pApduAuthenticate + nApduAuthenticateLen, &pLvSac, 1);
	nApduAuthenticateLen++;
	memcpy(pApduAuthenticate + nApduAuthenticateLen, pSAC, 32);
	nApduAuthenticateLen += 32;

	// Send AUTHENTICATE APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduAuthenticate, nApduAuthenticateLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_AUTHENTICATE_FIAL;
	}

	memcpy(pEncCRN, pRes, 16);
	memcpy(pICAC, pRes + 16, 64);

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int PutPerSamTEK(Byte* pEncTEK, Byte* pKCV, Byte* pResKCV, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00,0xA4,0x04,0x00,0x07,0xD4,0x10,0xB5,0x52,0x06,0x02,0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;
	
	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pPutKeyCmd[] = { 0x00,0xD8,0x00,0x10,0x13 };
	Byte pApduPutKey[256] = { 0, };
	int nApduPutKeyLen = 0;

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}
	
	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// PUT KEY APDU 持失
	memcpy(pApduPutKey, pPutKeyCmd, sizeof(pPutKeyCmd));
	nApduPutKeyLen += sizeof(pPutKeyCmd);

	memcpy(pApduPutKey + nApduPutKeyLen, pEncTEK, 16);
	nApduPutKeyLen += 16;

	memcpy(pApduPutKey + nApduPutKeyLen, pKCV, 3);
	nApduPutKeyLen += 3;


	// Send PUT KEY APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduPutKey, nApduPutKeyLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_PUT_KEY_ERROR;
	}

	memcpy(pResKCV, pRes, nResSize);

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int AddPerSamTK(Byte* nKvn, Byte* pEncTK, Byte* pKCV, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00,0xA4,0x04,0x00,0x07,0xD4,0x10,0xB5,0x52,0x06,0x02,0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pPutKeyCmd[] = { 0x00,0xD8,0x00,0x10,0x13 };
	Byte pApduPutKey[256] = { 0, };
	int nApduPutKeyLen = 0;

	Byte pApduGetCsn[] = { 0x00, 0xCA, 0x00, 0x00, 0x08 };

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// ADD KEY APDU 持失
	memcpy(pPutKeyCmd+2, nKvn, 1);

	memcpy(pApduPutKey, pPutKeyCmd, sizeof(pPutKeyCmd));
	nApduPutKeyLen += sizeof(pPutKeyCmd);

	memcpy(pApduPutKey + nApduPutKeyLen, pEncTK, 16);
	nApduPutKeyLen += 16;

	memcpy(pApduPutKey + nApduPutKeyLen, pKCV, 3);
	nApduPutKeyLen += 3;


	// Send PUT KEY APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduPutKey, nApduPutKeyLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_ADD_KEY_ERROR;
	}

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int GetPerSamKVN(Byte* pKvnList, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00,0xA4,0x04,0x00,0x07,0xD4,0x10,0xB5,0x52,0x06,0x02,0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pApduGetKvn[256] = { 0x00,0xCA,0x02,0x00,0x00 };

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// Send PUT KEY APDU
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetKvn, sizeof(pApduGetKvn), pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_AUTHENTICATE_FIAL;
	}

	memcpy(pKvnList, pRes, nResSize);

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

int TerminationChallenge(Byte* pSRN, Byte* pCRN, Byte* pRsltCode)
{
	Byte pApduSelect[] = { 0x00,0xA4,0x04,0x00,0x07,0xD4,0x10,0xB5,0x52,0x06,0x01,0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pApduChallenge[128] = { 0, };
	int nApduChallengeLen = 0;
	Byte pChallengeCmd[] = { 0x00, 0x84, 0x02, 0x00, 0x10 };

	int nReturnCode = SCardOpen();
	if (nReturnCode) {
		return IC_CARD_E_OPEN_FAIL;
	}

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);
	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		memcpy(pRsltCode, pStatusCode, 2);
		return IC_CARD_E_SELECT_ERROR;
	}

	// Send GET Challenge APDU
	// response - CRN
	memcpy(pApduChallenge, pChallengeCmd, sizeof(pChallengeCmd));
	nApduChallengeLen += sizeof(pChallengeCmd);
	memcpy(pApduChallenge + nApduChallengeLen, pSRN, 16);
	nApduChallengeLen += 16;

	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChallenge, nApduChallengeLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);

	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_GET_TERMINATION_CHALLENGE_ERROR;
	}

	memcpy(pCRN, pRes, 16);

	return IC_CARD_S_SUCCESS;
}

int TerminationICCard(Byte* pTSKEY, Byte* pTAC, Byte* pRsltCode)
{
	Byte pRes[1024] = { 0, };
	int nResSize = 0;

	Byte pStatusCode[2] = { 0, };
	Byte pSuccessCode[] = { 0x90, 0x00 };

	Byte pLvTsKey = 0x40;
	Byte pLvTac = 0x20;

	Byte pApduTermination[128] = { 0, };
	int nApduTerminationLen = 0;
	Byte pTerminationCmd[] = { 0x00,0xF0,0x00,0x00,0x62 };

	int nReturnCode = 0;

	// Termination
	memcpy(pApduTermination, pTerminationCmd, sizeof(pTerminationCmd));
	nApduTerminationLen += sizeof(pTerminationCmd);
	memcpy(pApduTermination + nApduTerminationLen, &pLvTsKey, 1);
	nApduTerminationLen++;
	memcpy(pApduTermination + nApduTerminationLen, pTSKEY, 64);
	nApduTerminationLen += 64;
	memcpy(pApduTermination + nApduTerminationLen, &pLvTac, 1);
	nApduTerminationLen++;
	memcpy(pApduTermination + nApduTerminationLen, pTAC, 32);
	nApduTerminationLen += 32;

	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduTermination, nApduTerminationLen, pRes, &nResSize, pStatusCode);
	memcpy(pRsltCode, pStatusCode, 2);

	if (memcmp(pStatusCode, pSuccessCode, 2) != 0)
	{
		SCardClose();
		return IC_CARD_E_GET_TERMINATION_CHALLENGE_ERROR;
	}

	SCardClose();

	return IC_CARD_S_SUCCESS;
}

void GetErrString(int errCode, Byte* errStr)
{
	switch (errCode) {
	case IC_CARD_S_SUCCESS:
		strcpy(errStr, "Success");
		break;
	case IC_CARD_E_INVALID_PARAM_LENGTH:
		strcpy(errStr, "Function Parame Length is invalid");
		break;
	case IC_CARD_E_OPEN_FAIL:
		strcpy(errStr, "ICCard connect fail");
		break;
	case IC_CARD_E_SELECT_ERROR:
		strcpy(errStr, "SELECT APDU Fail");
		break;
	case IC_CARD_E_GET_ICNO_ERROR:
		strcpy(errStr, "GET ICNO APDU Fail");
		break;
	case IC_CARD_E_GET_CHECK_HASH_ERROR:
		strcpy(errStr, "GET CHECK_HASH APDU Fail");
		break;
	case IC_CARD_E_GET_CHALLENGE_ERROR:
		strcpy(errStr, "GET CHALLENGE APDU Fail");
		break;
	case IC_CARD_E_CHANGE_PIN_FAIL:
		strcpy(errStr, "GET CHANGE PIN APDU Fail");
		break;
	case IC_CARD_E_UNBLOCK_PIN_FAIL:
		strcpy(errStr, "UNBLOCK PIN APDU Fail");
		break;
	case IC_CARD_E_VERIFY_PIN_FAIL:
		strcpy(errStr, "VERIFY PIN APDU Fail");
		break;
	case IC_CARD_E_AUTHENTICATE_FIAL:
		strcpy(errStr, "AUTHENTICATE APDU Fail");
		break;
	case IC_CARD_E_LIFE_CYCLE_ERROR:
		strcpy(errStr, "Life Cycle is invalid");
		break;
	case IC_CARD_E_PUT_KEY_ERROR:
		strcpy(errStr, "Put Key Error");
		break;
	case IC_CARD_E_MAKE_SEK_FAIL:
		strcpy(errStr, "Make Sek Fail");
		break;
	case IC_CARD_E_MAKE_SMK_FAIL:
		strcpy(errStr, "Make Smk Fail");
		break;
	case IC_CARD_E_MAKE_MAC_FAIL:
		strcpy(errStr, "Make Mac Fail");
		break;
	case IC_CARD_E_MAKE_ENC_USR_PIN_FAIL:
		strcpy(errStr, "Make Enc Usr Pin Fail");
		break;
	case IC_CARD_E_MAKE_ENC_UNBLOCK_PIN_FAIL:
		strcpy(errStr, "Make Enc Unblock Pin Fail");
		break;
	case IC_CARD_E_MAKE_ENC_PIN_FAIL:
		strcpy(errStr, "Make Enc Pin Fail");
		break;
		
	case IC_CARD_E_GET_DATA:
		strcpy(errStr, "Get Data Fail");
		break;
	
	case IC_CARD_E_ADD_KEY_ERROR:
		strcpy(errStr, "Persam Add Key Fail");
		break;

	case IC_CARD_E_REMAINING_PIN_TRY_ERROR:
		strcpy(errStr, "Get Remaining pin try Fail");
		break;

	case IC_CARD_E_GET_TERMINATION_CHALLENGE_ERROR:
		strcpy(errStr, "TERMINATION - Get Challenge Fail");
		break;
	
	case IC_CARD_E_GET_TERMINATION_ERROR:
		strcpy(errStr, "TERMINATION Fail");
		break;

	default:
		strcpy(errStr, "Unknown error code.");
		break;
	}
}

