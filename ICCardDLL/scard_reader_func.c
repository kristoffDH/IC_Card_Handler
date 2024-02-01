


#include "scard_reader_func.h"
#include "common.h"

#include <winscard.h>
#include <sys/stat.h>
#include <stdio.h>
#pragma comment (lib, "winscard.lib")

#define DEVICE_NAME_BUFF 256
#define MAX_APDU_LEN 1024
#define MAX_RESPONSE 1024

typedef unsigned char Byte;


SCARDCONTEXT g_hContextHandle;
SCARDHANDLE g_hCardHandle;
Byte g_pDeviceName[DEVICE_NAME_BUFF];
DWORD g_dwActiveProtocol;

#if LOG
// LOG 관련
#define LOG_DIR1 "C:\\ICCard"
#define LOG_DIR2 "C:\\ICCard\\log"
#define LOG_FILE LOG_DIR2##"\\log.txt"
FILE* g_fLog;
SYSTEMTIME g_lSysTime;
#endif

long SCardOpen()
{
	Byte pResponseBuffer[1024];
	ULONG lResponseLength = 1024;
	DWORD dwRv;

	memset(pResponseBuffer, 0x00, sizeof(pResponseBuffer));
	memset(g_pDeviceName, 0x00, sizeof(g_pDeviceName));

	dwRv = SCardEstablishContext(SCARD_SCOPE_USER,
		NULL,
		NULL,
		&g_hContextHandle);

	if (dwRv != SCARD_S_SUCCESS)
	{
		return dwRv;
	}

	dwRv = SCardListReaders(g_hContextHandle, 0,
		(char*)pResponseBuffer,
		&lResponseLength);

	if (dwRv != SCARD_S_SUCCESS)
	{
		return dwRv;
	}

	strcpy(g_pDeviceName, pResponseBuffer);

	dwRv = SCardConnect(g_hContextHandle,
		g_pDeviceName,
		SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&g_hCardHandle,
		&g_dwActiveProtocol);

	// log용 파일 open 및 시간 설정
#if LOG
	GetLocalTime(&g_lSysTime);
	mkdir(LOG_DIR1);
	mkdir(LOG_DIR2);
	g_fLog = fopen(LOG_FILE, "a");
#endif

	return dwRv;
}

void SCardClose()
{
	SCardDisconnect(g_hCardHandle, SCARD_EJECT_CARD);

#if LOG
	// log용 파일 close
	fclose(g_fLog);
#endif
}

long SCardReset()
{
	DWORD               dwATRLength = 40;
	Byte                pATR[40];
	DWORD               dwLength = DEVICE_NAME_BUFF;
	DWORD               dwCardState = 0;
	DWORD               dwActiveProtocol = 0;

	DWORD dwRv;

	dwRv = SCardReconnect(g_hCardHandle,
		SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		SCARD_UNPOWER_CARD,
		&dwActiveProtocol);

	if (dwRv != SCARD_S_SUCCESS)
	{
		return dwRv;
	}

	memset(pATR, 0x00, sizeof(pATR));

	dwRv = SCardStatus(g_hCardHandle,
		g_pDeviceName,
		&dwLength,
		&dwCardState,
		&dwActiveProtocol,
		pATR,
		&dwATRLength);

	return dwRv;
}

long SCardTransmitAPDU(Byte* pApdu, int nApduLen, Byte* pResponse, int* nResponseLen, Byte* pStatusCode)
{
	Byte pRecvData[MAX_RESPONSE];
	ULONG nResSize = MAX_RESPONSE;
	SCARD_IO_REQUEST IO_Request;
	DWORD dwRv = 0;

#if LOG
	// Send APDU Log
	Byte pLogData[1024] = { 0, };
	fprintf(g_fLog, "[%04d-%02d-%02d %02d:%02d:%02d] Send APDU : ", 
		g_lSysTime.wYear, 
		g_lSysTime.wMonth, 
		g_lSysTime.wDay, 
		g_lSysTime.wHour, 
		g_lSysTime.wMinute, 
		g_lSysTime.wSecond);

	Hex2Asc(pLogData, pApdu, nApduLen);
	fprintf(g_fLog, "%s\n", pLogData);
	// Log END
#endif

	memset(pRecvData, 0x00, MAX_APDU_LEN);

	IO_Request.dwProtocol = g_dwActiveProtocol;
	IO_Request.cbPciLength = (DWORD)sizeof(SCARD_IO_REQUEST);

	dwRv = SCardTransmit(g_hCardHandle,
		&IO_Request,
		pApdu,
		nApduLen,
		0,
		pRecvData,
		&nResSize);

	if (dwRv != SCARD_S_SUCCESS) {

		return dwRv;
	}

	if (nResSize != 0)
	{
		*nResponseLen = nResSize - 2;
		memcpy(pResponse, pRecvData, *nResponseLen);
		memcpy(pStatusCode, pRecvData + *nResponseLen, 2);
	}

#if LOG
	// Recv APDU Log
	fprintf(g_fLog, "[%04d-%02d-%02d %02d:%02d:%02d] Recv APDU : ",
		g_lSysTime.wYear,
		g_lSysTime.wMonth,
		g_lSysTime.wDay,
		g_lSysTime.wHour,
		g_lSysTime.wMinute,
		g_lSysTime.wSecond);

	Hex2Asc(pLogData, pRecvData, nResSize);
	fprintf(g_fLog, "%s\n", pLogData);
#endif

	return dwRv;
}

int SCardGetErrCode(long lErrCode)
{
	switch (lErrCode) {
	case SCARD_E_CANCELLED:
		return 0x1001;
	case SCARD_E_CANT_DISPOSE:
		return 0x1002;
	case SCARD_E_CARD_UNSUPPORTED:
		return 0x1003;
	case SCARD_E_DUPLICATE_READER:
		return 0x1004;
	case SCARD_E_INSUFFICIENT_BUFFER:
		return 0x1005;
	case SCARD_E_INVALID_ATR:
		return 0x1006;
	case SCARD_E_INVALID_HANDLE:
		return 0x1007;
	case SCARD_E_INVALID_PARAMETER:
		return 0x1008;
	case SCARD_E_INVALID_TARGET:
		return 0x1009;
	case SCARD_E_INVALID_VALUE:
		return 0x100A;
	case SCARD_E_NOT_READY:
		return 0x100B;
	case SCARD_E_NOT_TRANSACTED:
		return 0x100C;
	case SCARD_E_NO_MEMORY:
		return 0x100D;
	case SCARD_E_NO_SERVICE:
		return 0x100E;
	case SCARD_E_NO_SMARTCARD:
		return 0x100F;
	case SCARD_E_PCI_TOO_SMALL:
		return 0x1010;
	case SCARD_E_PROTO_MISMATCH:
		return 0x1011;
	case SCARD_E_READER_UNAVAILABLE:
		return 0x1012;
	case SCARD_E_READER_UNSUPPORTED:
		return 0x1013;
	case SCARD_E_SERVICE_STOPPED:
		return 0x1014;
	case SCARD_E_SHARING_VIOLATION:
		return 0x1015;
	case SCARD_E_SYSTEM_CANCELLED:
		return 0x1016;
	case SCARD_E_TIMEOUT:
		return 0x1017;
	case SCARD_E_UNKNOWN_CARD:
		return 0x1018;
	case SCARD_E_UNKNOWN_READER:
		return 0x1019;
	case SCARD_F_COMM_ERROR:
		return 0x101A;
	case SCARD_F_INTERNAL_ERROR:
		return 0x101B;
	case SCARD_F_UNKNOWN_ERROR:
		return 0x101C;
	case SCARD_F_WAITED_TOO_LONG:
		return 0x101D;
	case SCARD_W_REMOVED_CARD:
		return 0x101E;
	case SCARD_W_RESET_CARD:
		return 0x101F;
	case SCARD_W_UNPOWERED_CARD:
		return 0x1020;
	case SCARD_W_UNRESPONSIVE_CARD:
		return 0x1021;
	case SCARD_W_UNSUPPORTED_CARD:
		return 0x1022;
	default:
		return 0x10FF;
		break;
	}
}

int SCardTest(Byte* pOutput)
{
	int rv = SCardOpen();

	if (rv) {
		return;
	}
		

	SCardReset();
	
	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;
	Byte pStatusCode[2] = { 0, };

	Byte tmpStr[2048] = { 0, };
	int nSize = 0;
	int nPos = 0;

	Byte pApduGetCheckHash[] = { 0x00, 0xCA, 0x00, 0xFF, 0x20 };
	Byte pApduGetIcno[] = { 0x20,0x21,0x09,0x00,0x00,0x01,0x00,0x00,0x00,0x04 };
	
	Byte pCheckHash[256] = { 0, };
	int nCheckHashLen = 0;


	Byte pApduGetChallenge[] = { 0x00,0x84,0x00,0x00,0x10,0xC9,0x87,0xB0,0xF4,0x13,0x8A,0x8B,0x25,0x3F,0x4F,0x7E,0x13,0x9A,0x0A,0x97,0x8F };

	Byte pCRN[256] = { 0, };
	int nCrnLen = 0;

	Byte pApduChangePin[] = { 0x84,0x24,0x00,0x00,0x18,0x76,0xC5,0xDF,0x96,0x45,0x18,0x7F,0x89,0x98,0x61,0x8D,0xD7,0xAC,0x4E,0xF8,0xDA,0x41,0x63,0xC8,0x97,0x12,0xF3,0x6A,0x92 };

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("select", pApduSelect, sizeof(pApduSelect), tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Select - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;


	// get data(check hash)
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetCheckHash, sizeof(pApduGetCheckHash), pRes, &nResSize, pStatusCode);
	memcpy(pCheckHash, pRes, nResSize);
	nCheckHashLen = nResSize;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CHECK HASH - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CHECK HASH", pCheckHash, nCheckHashLen, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;


	// get challenge 
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetChallenge, sizeof(pApduGetChallenge), pRes, &nResSize, pStatusCode);
	memcpy(pCRN, pRes, nResSize);
	nCrnLen= nResSize;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Challenge - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CRN", pCRN, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;
	

	// change pin
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChangePin, sizeof(pApduChangePin), pRes, &nResSize, pStatusCode);

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Change pin - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	SCardClose();

	return nPos;
}


#if 0
// Activation TEST
int SCardTest(Byte* pOutput)
{
	int rv = SCardOpen();

	if (rv) {
		return;
	}


	SCardReset();

	Byte pApduSelect[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD4, 0x10, 0xB5, 0x52, 0x06, 0x01, 0x01 };
	Byte pRes[1024] = { 0, };
	int nResSize = 0;
	Byte pStatusCode[2] = { 0, };

	Byte tmpStr[2048] = { 0, };
	int nSize = 0;
	int nPos = 0;

	Byte pApduGetCheckHash[] = { 0x00, 0xCA, 0x00, 0xFF, 0x20 };
	Byte pApduGetIcno[] = { 0x20,0x21,0x09,0x00,0x00,0x01,0x00,0x00,0x00,0x04 };

	Byte pCheckHash[256] = { 0, };
	int nCheckHashLen = 0;


	Byte pApduGetChallenge[] = { 0x00,0x84,0x00,0x00,0x10,0xC9,0x87,0xB0,0xF4,0x13,0x8A,0x8B,0x25,0x3F,0x4F,0x7E,0x13,0x9A,0x0A,0x97,0x8F };

	Byte pCRN[256] = { 0, };
	int nCrnLen = 0;

	Byte pApduChangePin[] = { 0x84,0x24,0x00,0x00,0x18,0x76,0xC5,0xDF,0x96,0x45,0x18,0x7F,0x89,0x98,0x61,0x8D,0xD7,0xAC,0x4E,0xF8,0xDA,0x41,0x63,0xC8,0x97,0x12,0xF3,0x6A,0x92 };

	SCardReset();

	// select
	SCardTransmitAPDU(pApduSelect, sizeof(pApduSelect), pRes, &nResSize, pStatusCode);

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("select", pApduSelect, sizeof(pApduSelect), tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Select - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;


	// get data(check hash)
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetCheckHash, sizeof(pApduGetCheckHash), pRes, &nResSize, pStatusCode);
	memcpy(pCheckHash, pRes, nResSize);
	nCheckHashLen = nResSize;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CHECK HASH - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CHECK HASH", pCheckHash, nCheckHashLen, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;


	// get challenge 
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduGetChallenge, sizeof(pApduGetChallenge), pRes, &nResSize, pStatusCode);
	memcpy(pCRN, pRes, nResSize);
	nCrnLen = nResSize;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Challenge - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("CRN", pCRN, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;


	// change pin
	memset(pRes, 0x00, sizeof(pRes));
	SCardTransmitAPDU(pApduChangePin, sizeof(pApduChangePin), pRes, &nResSize, pStatusCode);

	memset(tmpStr, 0x00, sizeof(tmpStr));
	nSize += ConvertBlockOfLength("Change pin - RES", pStatusCode, 2, tmpStr);
	memcpy(pOutput + nPos, tmpStr, nSize);
	nPos += nSize;
	nSize = 0;

	SCardClose();

	return nPos;
}

#endif