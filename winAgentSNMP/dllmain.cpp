// dllmain.cpp : Defines the entry point for the DLL application.

#include <snmp.h>


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BOOL bReturn = TRUE;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//ghEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		//CloseHandle( ghEvent );
		break;
	}
	return (bReturn);
}

/*********************************************************************************/
#define OID_SIZEOF(x) (sizeof(x)/sizeof(int))


UINT g_unMyOIDPrefix[]	= { 1,3,6,1,4,1,36872 };
AsnObjectIdentifier mibOid = { OID_SIZEOF(g_unMyOIDPrefix),g_unMyOIDPrefix };

HANDLE	ghTrapEvent;
HANDLE	ghPollThread;
DWORD	gdwAgentStartTime;
DWORD	gdwMonitorThreadId;

struct MIB_ENTRY
{
	AsnObjectIdentifier asnOid;
	void *              pStorageValue;
	CHAR *              szStorageName;
	BYTE                chType;
	UINT                unAccess;
	MIB_ENTRY*			pMibNext;
};

UINT g_unAboutOid[]		= { 1 };
UINT g_unNameOid[]		= { 2 };
UINT g_unAgeOid[]		= { 3 };
UINT g_txPortOid[]		= { 2, 1, 1, 4, 1, 5 };
char g_szAbout[40]		= "Hello, World!";
char g_szName[40]		= "James Gosnell";
AsnInteger g_asnAge		= 31;
AsnInteger g_asnTxPort	= 23;

/// This is the MIB table and its related variable store
//    here evry thing is hard-coded to demonstration perpose
//    Actualy it should be loaded from the registry or from some file
MIB_ENTRY gMibTable[] = 
{
	{ { OID_SIZEOF(g_unAboutOid),g_unAboutOid},&g_szAbout,"About",ASN_OCTETSTRING,SNMP_ACCESS_READ_WRITE,&gMibTable[1] },
	{ { OID_SIZEOF(g_unNameOid) ,g_unNameOid} ,&g_szName ,"Name" ,ASN_OCTETSTRING,SNMP_ACCESS_READ_WRITE,&gMibTable[2] },
	{ { OID_SIZEOF(g_unAgeOid)  ,g_unAgeOid}  ,&g_asnAge ,"Age"  ,  ASN_INTEGER  ,SNMP_ACCESS_READ_WRITE,&gMibTable[3] },
	{ { OID_SIZEOF(g_txPortOid) ,g_txPortOid} ,&g_asnTxPort ,"txPort",ASN_INTEGER,SNMP_ACCESS_READ_WRITE,NULL   },
};
 
int getStoreVar(MIB_ENTRY*,AsnAny*);

BOOL WINAPI SnmpExtensionInit (
	IN	DWORD				dwTimeZeroReference,
	OUT	HANDLE				*phPollForTrapEvent,
	OUT	AsnObjectIdentifier	*pSupportedView )
{
	#if _DEBUG
		SnmpSvcSetLogLevel(SNMP_LOG_VERBOSE);
		SnmpSvcSetLogType(SNMP_OUTPUT_TO_LOGFILE);
	#else
		SnmpSvcSetLogLevel(SNMP_LOG_ERROR);
		SnmpSvcSetLogType(SNMP_OUTPUT_TO_LOGFILE);
	#endif

	BOOL fResult = TRUE;
	*phPollForTrapEvent = NULL;
	*pSupportedView = mibOid;
	/*
	*phPollForTrapEvent = CreateEvent ( NULL, FALSE, FALSE, NULL );
	
	if ( *phPollForTrapEvent != NULL )
	{
		ghTrapEvent = *phPollForTrapEvent;
		*pSupportedView = MibOid;
		gdwAgentStartTime = dwTimeZeroReference;

		ghPollThread = CreateThread ( NULL, 0, (LPTHREAD_START_ROUTINE)MonitorThread, 0, 0, &gdwMonitorThreadId );

	}
	else fResult = FALSE;
	*/
	return (fResult);
}

BOOL WINAPI	SnmpExtensionQuery (
	IN BYTE                   bRequestType,
    IN OUT RFC1157VarBindList *pVariableBindingsList,
    OUT AsnInteger            *pErrorStatus,
    OUT AsnInteger            *pErrorIndex
	)
{

	BOOL fResult	= TRUE;
	*pErrorStatus	= SNMP_ERRORSTATUS_NOERROR;
	//*pErrorStatus	= SNMP_ERRORSTATUS_TOOBIG;
	*pErrorIndex	= 0;

	UINT i;
	for (i=0; i < pVariableBindingsList->len; i++)

	{
		//*pErrorStatus = getStoreVar( &gMibTable[i], &pVariableBindings->list[i].value);
		fResult = SnmpUtilOidCpy	(&pVariableBindingsList->list[i].name, &mibOid);
		fResult = SnmpUtilOidAppend	(&pVariableBindingsList->list[i].name, &gMibTable[i].asnOid);
		//fResult = SnmpUtilVarBindCpy(&pVariableBindingsList->list[i], &gMibTable[i]);

		//*pErrorStatus = getStoreVar( &gMibTable[i], &pVariableBindingsList->list[i].value);
		
		*pErrorIndex = i;

/*
		SnmpUtilDbgPrint(
			SNMP_OUTPUT_TO_LOGFILE,   // see log levels from snmp.h
			"VarBind[%d]: %s\n",
			i,
			getStoreVar(&gMibTable[i], &pVariableBindingsList->list[i].value)
		);
*/
		SnmpUtilDbgPrint(
			SNMP_OUTPUT_TO_LOGFILE,   // see log levels from snmp.h
			"VarBind[%d]:\n",
			i
		);
		*pErrorStatus = getStoreVar(&gMibTable[i], &pVariableBindingsList->list[i].value);

	}

	return (fResult);
}


int getStoreVar(MIB_ENTRY* pMIB, AsnAny *pasnValue)
{
	// check rights is there to access
	if((pMIB->unAccess != SNMP_ACCESS_READ_ONLY)&&(pMIB->unAccess != SNMP_ACCESS_READ_WRITE)&&(pMIB->unAccess != SNMP_ACCESS_READ_CREATE))
		return SNMP_ERRORSTATUS_GENERR;

	// set the type
	pasnValue->asnType = pMIB->chType;
	
	switch(pasnValue->asnType)
	{
	case ASN_INTEGER:
		pasnValue->asnValue.number = *(AsnInteger32*)pMIB->pStorageValue;
		break;
	case ASN_COUNTER32:
	case ASN_GAUGE32:
	case ASN_TIMETICKS:
	case ASN_UNSIGNED32:
		pasnValue->asnValue.unsigned32 = *(AsnUnsigned32*)pMIB->pStorageValue;
		break;
	case ASN_OCTETSTRING:
		pasnValue->asnValue.string.length = strlen((char*)pMIB->pStorageValue);
		pasnValue->asnValue.string.stream =(unsigned char*)SnmpUtilMemAlloc(pasnValue->asnValue.string.length * sizeof(char));
		strncpy ((char*)pasnValue->asnValue.string.stream,g_szName, pasnValue->asnValue.string.length);
		pasnValue->asnValue.string.dynamic = TRUE;
		pasnValue->asnValue.string.stream[pasnValue->asnValue.string.length] = 0;
		break;
	case ASN_COUNTER64:
		pasnValue->asnValue.counter64 = *(AsnCounter64*)pMIB->pStorageValue;
		break;
	case ASN_OBJECTIDENTIFIER:
		SnmpUtilOidCpy(&pasnValue->asnValue.object,(AsnObjectIdentifier*)pMIB->pStorageValue);
		break;
	case ASN_IPADDRESS:
		pasnValue->asnValue.address.length = 4;
		pasnValue->asnValue.string.dynamic = TRUE;

		pasnValue->asnValue.address.stream[0] = ((char*)pMIB->pStorageValue)[0];
		pasnValue->asnValue.address.stream[1] = ((char*)pMIB->pStorageValue)[1];
		pasnValue->asnValue.address.stream[2] = ((char*)pMIB->pStorageValue)[2];
		pasnValue->asnValue.address.stream[3] = ((char*)pMIB->pStorageValue)[3];
		break;
	case ASN_OPAQUE:
		AsnSequence;
		break;
	case ASN_BITS:
		break;	
	case ASN_SEQUENCE:
		break;	
	case ASN_NULL:
	default:
		return SNMP_ERRORSTATUS_GENERR;	
	}
	return SNMP_ERRORSTATUS_NOERROR;
}

/*
BOOL WINAPI SnmpExtensionTrap (
    OUT AsnObjectIdentifier *enterprise,
    OUT AsnInteger          *genericTrap,
    OUT AsnInteger          *specificTrap,
    OUT AsnTimeticks        *timeStamp,
    OUT RFC1157VarBindList  *variableBindings)
{
	return TRUE;
}
*/