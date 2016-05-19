#include <windows.h>
#include <tchar.h>
#include <WinDNS.h>
#include <xmllite.h>
#include "banned.h"

#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

#define _SDL_BANNED_RECOMMENDED

// DNS addresses used by McAfee GTI aka Artemis
LPCWSTR AVTS_DNS_NAME = L"sfqpit75pjh525siewar2dtgt5.avts.mcafee.com"; //McAfee KB53733 
LPCWSTR AVQS_DNS_NAME = L"4z9p5tjmcbnblehp4557z1d136.avqs.mcafee.com"; //McAfee KB53735

LPCWSTR VSE_SERVICE_NAME = L"McShield";

// registry paths
LPCWSTR AVENGINE_32_REG_PATH = L"SOFTWARE\\McAfee\\AVEngine";
LPCWSTR AVENGINE_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\AVEngine";
LPCWSTR SYSTEM_CORE_32_REG_PATH = L"SOFTWARE\\McAfee\\SystemCore";
LPCWSTR SYSTEM_CORE_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\SystemCore";
LPCWSTR DESKTOP_PROTECTION_32_REG_PATH  = L"SOFTWARE\\McAfee\\DesktopProtection";
LPCWSTR DESKTOP_PROTECTION_64_REG_PATH  = L"SOFTWARE\\Wow6432Node\\McAfee\\DesktopProtection";
LPCWSTR TASKS_32_REG_PATH = L"SOFTWARE\\McAfee\\DesktopProtection\\Tasks";
LPCWSTR TASKS_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\DesktopProtection\\Tasks";
LPCWSTR EMAIL_SCANNER_32_REG_PATH = L"SOFTWARE\\McAfee\\SystemCore\\VSCore\\Email Scanner";
LPCWSTR EMAIL_SCANNER_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\SystemCore\\VSCore\\Email Scanner";
LPCWSTR OUTLOOK_OPTIONS_32_REG_PATH = L"SOFTWARE\\McAfee\\SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\GeneralOptions";
LPCWSTR OUTLOOK_OPTIONS_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\GeneralOptions";
LPCWSTR SCANNER_32_REG_PATH = L"SOFTWARE\\McAfee\\SystemCore\\VSCore\\On Access Scanner";
LPCWSTR SCANNER_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\SystemCore\\VSCore\\On Access Scanner";
LPCWSTR MCSHIELD_CONFIG_32_REG_PATH = L"SOFTWARE\\McAfee\\SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration";
LPCWSTR MCSHIELD_CONFIG_64_REG_PATH = L"SOFTWARE\\Wow6432Node\\McAfee\\SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration";

// registry value names
LPCWSTR AVDAT_DATE_REG_NAME = L"AVDatDate";
LPCWSTR AVDAT_VERSION_REG_NAME = L"AVDatVersion";
LPCWSTR AVDAT_VERSION_MINOR_REG_NAME= L"AVDatVersionMinor";
LPCWSTR AVENGINE_MAJOR_REG_NAME = L"EngineVersionMajor";
LPCWSTR AVENGINE_MINOR_REG_NAME = L"EngineVersionMinor";
LPCWSTR SYSTEM_CORE_REG_NAME = L"system_core_version";
LPCWSTR PRODUCT_VERSION_REG_NAME = L"szProductVer";
LPCWSTR ARTEMIS_ENABLED_REG_NAME = L"ArtemisEnabled";
LPCWSTR ARTEMIS_LEVEL_REG_NAME = L"ArtemisLevel";
LPCWSTR START_DISABLED_NAME = L"bStartDisabled";

// XML element names
LPCWSTR AV_ROOT_ELEMENT = L"LL_AV";
LPCWSTR MCAFEE_ELEMENT = L"McAfeeVSE";
LPCWSTR ARTEMIS_ELEMENT = L"Artemis";
LPCWSTR DNS_ELEMENT = L"DNS";
LPCWSTR QUERY_ELEMENT = L"Query";
LPCWSTR COMPONENT_ELEMENT = L"Component";
LPCWSTR ENABLED_ELEMENT = L"Enabled";
LPCWSTR LEVEL_ELEMENT = L"Level";
LPCWSTR SERVICE_ELEMENT = L"Service";
LPCWSTR STATE_ELEMENT = L"State";
LPCWSTR START_ELEMENT = L"Start";
LPCWSTR DISABLED_ELEMENT = L"Disabled";
LPCWSTR DAT_ELEMENT = L"DAT";
LPCWSTR DATE_ELEMENT = L"Date";
LPCWSTR DAT_VER_MAJ_ELEMENT = L"VersionMajor";
LPCWSTR DAT_VER_MIN_ELEMENT = L"VersionMinor";
LPCWSTR VER_ELEMENT = L"Version";
LPCWSTR AV_VER_MAJ_ELEMENT = L"AVEngineMajor";
LPCWSTR AV_VER_MIN_ELEMENT = L"AVEngineMinor";
LPCWSTR CORE_VER_ELEMENT = L"SystemCore";
LPCWSTR PRODUCT_ELEMENT = L"Product";

// XML attribute names
LPCWSTR INSTALLED_ATTRIBUTE = L"Installed";
LPCWSTR NAME_ATTRIBUTE = L"Name";

// component names used as values for Artemis components
LPCWSTR DP_COMPONENT = L"DesktopProtection";
LPCWSTR ES_COMPONENT = L"Email Scanner";
LPCWSTR OUTLOOK_COMPONENT = L"Outlook";
LPCWSTR OAS_COMPONENT = L"On Access Scanner";

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

/*
Determines if the process is running under Wow64
*/
BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(L"kernel32.dll"),"IsWow64Process");

	if(NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
		{
			//could handle error but for now return as FALSE
		}
	}
	return bIsWow64;
}


#define HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) \
	: ((HRESULT)(((x)& 0x0000ffff) | (FACILITY_WIN32 << 16) | 0x80000000)))


// This class is from a Microsoft code sample.
class FileStream : public IStream
{

public:
	FileStream(HANDLE hFile)
	{
		_refcount = 1;
		_hFile = hFile;
	}

	~FileStream()
	{
		if (_hFile != INVALID_HANDLE_VALUE && _hFile != GetStdHandle(STD_OUTPUT_HANDLE))
		{
			::CloseHandle(_hFile);
		}
	}


	HRESULT static OpenFile(LPCWSTR pName, IStream ** ppStream, bool fWrite)
	{
		HANDLE hFile = ::CreateFileW(pName, fWrite ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ,
			NULL, fWrite ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
			return HRESULT_FROM_WIN32(GetLastError());

		*ppStream = new FileStream(hFile);

		if (*ppStream == NULL)
			CloseHandle(hFile);

		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, __RPC__deref_out _Result_nullonfailure_ void __RPC_FAR *__RPC_FAR *ppvObject)
	{
		if (!ppvObject)
			return E_INVALIDARG;
		(*ppvObject) = NULL;

		if (iid == __uuidof(IUnknown)
			|| iid == __uuidof(IStream)
			|| iid == __uuidof(ISequentialStream))
		{
			*ppvObject = static_cast<IStream*>(this);
			AddRef();
			return S_OK;
		}
		else
			return E_NOINTERFACE;
	}

	virtual ULONG STDMETHODCALLTYPE AddRef(void)
	{
		return (ULONG)InterlockedIncrement(&_refcount);
	}

	virtual ULONG STDMETHODCALLTYPE Release(void)
	{
		ULONG res = (ULONG)InterlockedDecrement(&_refcount);
		if (res == 0)
			delete this;
		return res;
	}

	// ISequentialStream Interface
public:
	virtual HRESULT STDMETHODCALLTYPE Read(_Out_writes_bytes_to_(cb, *pcbRead) void* pv, _In_ ULONG cb, _Out_opt_ ULONG* pcbRead)
	{
		BOOL rc = ReadFile(_hFile, pv, cb, pcbRead, NULL);
		return (rc) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	virtual HRESULT STDMETHODCALLTYPE Write(_In_reads_bytes_(cb) const void* pv, _In_ ULONG cb, _Out_opt_ ULONG* pcbWritten)
	{
		BOOL rc = WriteFile(_hFile, pv, cb, pcbWritten, NULL);
		return rc ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	// IStream Interface
public:
	virtual HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE CopyTo(_In_ IStream*, ULARGE_INTEGER, _Out_opt_ ULARGE_INTEGER*, _Out_opt_ ULARGE_INTEGER*)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE Commit(DWORD)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE Revert(void)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE Clone(__RPC__deref_out_opt IStream **)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER liDistanceToMove, DWORD dwOrigin, _Out_opt_ ULARGE_INTEGER* lpNewFilePointer)
	{
		DWORD dwMoveMethod;

		switch (dwOrigin)
		{
		case STREAM_SEEK_SET:
			dwMoveMethod = FILE_BEGIN;
			break;
		case STREAM_SEEK_CUR:
			dwMoveMethod = FILE_CURRENT;
			break;
		case STREAM_SEEK_END:
			dwMoveMethod = FILE_END;
			break;
		default:
			return STG_E_INVALIDFUNCTION;
			break;
		}

		if (SetFilePointerEx(_hFile, liDistanceToMove, (PLARGE_INTEGER)lpNewFilePointer,
			dwMoveMethod) == 0)
			return HRESULT_FROM_WIN32(GetLastError());
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE Stat(__RPC__out STATSTG* pStatstg, DWORD)
	{
		if (GetFileSizeEx(_hFile, (PLARGE_INTEGER)&pStatstg->cbSize) == 0)
			return HRESULT_FROM_WIN32(GetLastError());
		return S_OK;
	}

private:
	HANDLE _hFile;
	LONG _refcount;
};


/*
Outputs an XML element name, as specified by the outputName parameter, based on the read DWORD value for registry value name that is passed.
*/
void OutputRegistryDWORD(HKEY key, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR outputName, IXmlWriter *pWriter)
{
	HKEY hKey;
	DWORD value;
	DWORD size = sizeof(DWORD);
	WCHAR buf[MAX_PATH] = {0};
	LSTATUS ret = 0;

	SecureZeroMemory(buf, sizeof(buf));

	ret = RegOpenKeyExW(key, subKey, 0, KEY_READ, &hKey);

	pWriter->WriteStartElement(NULL, outputName, NULL);

	if (ret == ERROR_SUCCESS)
	{
		ret = RegQueryValueExW(hKey, valueName, NULL, NULL, (LPBYTE)&value, &size);

		if (ret == ERROR_SUCCESS)
		{
			swprintf_s(buf, MAX_PATH - 1, L"%d", value);
			pWriter->WriteString(buf);
		}
		else
		{
			swprintf_s(buf, MAX_PATH - 1, L"FAILED on RegQueryValueEx: %d", ret);
			pWriter->WriteString(buf);
		}
		RegCloseKey(hKey);
	}
	else
	{
		swprintf_s(buf, MAX_PATH - 1, L"FAILED on RegOpenKeyEx: %d", ret);
		pWriter->WriteString(buf);
	}	

	SecureZeroMemory(buf, sizeof(buf));

	pWriter->WriteEndElement(); //end outputName
	pWriter->Flush();
}

/*
Outputs an XML element name, as specified by the outputName parameter, based on the read string value for registry value name that is passed.
*/
void OutputRegistryString(HKEY key, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR outputName, IXmlWriter *pWriter)
{
	HKEY hKey;
	WCHAR value[MAX_PATH] = {0};
	DWORD size = sizeof(WCHAR) * (MAX_PATH-1);
	WCHAR buf[MAX_PATH] = {0};
	LSTATUS ret = 0;

	SecureZeroMemory(buf, sizeof(buf));
	SecureZeroMemory(value, sizeof(value));

	ret = RegOpenKeyExW(key, subKey, 0, KEY_READ, &hKey);

	pWriter->WriteStartElement(NULL, outputName, NULL);

	if (ret == ERROR_SUCCESS)
	{
		ret = RegQueryValueExW(hKey, valueName, NULL, NULL, (LPBYTE)&value, &size);

		if (ret == ERROR_SUCCESS)
		{
			pWriter->WriteString(value);
		}
		else
		{
			swprintf_s(buf, MAX_PATH - 1, L"FAILED on RegQueryValueEx: %d", ret);
			pWriter->WriteString(buf);
		}
		RegCloseKey(hKey);
	}
	else
	{
		swprintf_s(buf, MAX_PATH - 1, L"FAILED on RegOpenKeyEx: %d", ret);
		pWriter->WriteString(buf);
	}	

	SecureZeroMemory(buf, sizeof(buf));
	SecureZeroMemory(value, sizeof(value));

	pWriter->WriteEndElement(); //end outputName
	pWriter->Flush();
}

/*
Determines if a registry path exists.
*/
BOOL RegistryPathExists(HKEY key, LPCWSTR path)
{
	LSTATUS ret = 0;
	HKEY hKey;

	ret = RegOpenKeyExW(key, path, 0, KEY_READ, &hKey);

	if(ret == ERROR_SUCCESS) 
	{
		RegCloseKey(hKey);
	}

	return ((ret == ERROR_SUCCESS) ? TRUE : FALSE);
}

/*
Determines if a service exists.
*/
BOOL ServiceNameExists(LPCWSTR name)
{
	SC_HANDLE serviceManagerHandle = NULL;
	SC_HANDLE serviceHandle = NULL;
	BOOL exists = FALSE;

	serviceManagerHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);

	if(NULL != serviceManagerHandle)
	{
		serviceHandle = OpenServiceW(serviceManagerHandle, name, SC_MANAGER_CONNECT);

		if(NULL != serviceHandle)
		{
			exists = TRUE;
			CloseServiceHandle(serviceHandle);
		}

		CloseServiceHandle(serviceManagerHandle);
	}

	return exists;
}

/*
Determines if McAfee VSE is installed.
*/
BOOL IsMcAfeeVSEInstalled() 
{
	BOOL installed = FALSE;
	BOOL registryExists = FALSE;
	BOOL serviceExists = FALSE;

	BOOL useWow6432Node = IsWow64();

	LPCWSTR regPath = useWow6432Node ? AVENGINE_64_REG_PATH : AVENGINE_32_REG_PATH ;

	registryExists = RegistryPathExists(HKEY_LOCAL_MACHINE, regPath);

	serviceExists = ServiceNameExists(VSE_SERVICE_NAME);

	// could do an additional check with _access_s to see if a particular file exists too

	installed = (registryExists && serviceExists);

	return installed;
}

void OutputServiceInformation(LPCWSTR name, IXmlWriter *pWriter)
{
	SC_HANDLE serviceManagerHandle = NULL;
	SC_HANDLE serviceHandle = NULL;
	SERVICE_STATUS status = {0};
	LPQUERY_SERVICE_CONFIG serviceConfig = {0};
	DWORD needed = 0;
	BOOL result = FALSE;
	WCHAR buf[MAX_PATH] = {0};

	BOOL useWow6432Node = IsWow64();
	LPCWSTR regPath = useWow6432Node ? MCSHIELD_CONFIG_64_REG_PATH : MCSHIELD_CONFIG_32_REG_PATH;

	SecureZeroMemory(buf, sizeof(buf));

	pWriter->WriteStartElement(NULL, SERVICE_ELEMENT, NULL);
	pWriter->WriteAttributeString(NULL, NAME_ATTRIBUTE, NULL, name);

	serviceManagerHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);

	if(NULL != serviceManagerHandle)
	{
		serviceHandle = OpenServiceW(serviceManagerHandle, name, GENERIC_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);

		if(NULL != serviceHandle)
		{
			result = QueryServiceStatus(serviceHandle, &status);

			if(result)
			{
				swprintf_s(buf, MAX_PATH - 1, L"%d", status.dwCurrentState); // 1 = stopped, 2 = start pending, 3 = stop pending, 4 = running, 5 = continue pending, 6 = pause pending, 7 = paused
				pWriter->WriteElementString(NULL, STATE_ELEMENT, NULL, buf);
			}

			QueryServiceConfigW(serviceHandle, NULL, 0, &needed);

			serviceConfig = (LPQUERY_SERVICE_CONFIG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);

			if (NULL != serviceConfig) {

				result = QueryServiceConfigW(serviceHandle, serviceConfig, needed, &needed);

				if(result)
				{
					SecureZeroMemory(buf, sizeof(buf));
					swprintf_s(buf, MAX_PATH - 1, L"%d", serviceConfig->dwStartType); // 0 = boot, 1  = system, 2 = auto, 3 = demand/manual, 4 = disabled
					pWriter->WriteElementString(NULL, START_ELEMENT, NULL, buf);
					SecureZeroMemory(serviceConfig, needed);
					HeapFree(GetProcessHeap(), 0, serviceConfig);
					serviceConfig = NULL;
				}
			}

			CloseServiceHandle(serviceHandle);
		}

		CloseServiceHandle(serviceManagerHandle);
	}

	SecureZeroMemory(buf, sizeof(buf));

	OutputRegistryDWORD(HKEY_LOCAL_MACHINE, regPath, START_DISABLED_NAME, DISABLED_ELEMENT, pWriter);

	pWriter->WriteEndElement();
	pWriter->Flush();
}

/*
Outputs an XML element based on the success or failure of a DNS lookup.
*/
void OutputDnsQuery(LPCWSTR dns, IXmlWriter *pWriter)
{
	DNS_STATUS status;
	PDNS_RECORD pDnsRecord = {0};
	IN_ADDR ipaddr = {0};
	wchar_t buf[MAX_PATH] = {0};

	SecureZeroMemory(buf, sizeof(buf));

	status = DnsQuery(dns, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &pDnsRecord, NULL);

	pWriter->WriteStartElement(NULL, QUERY_ELEMENT, NULL);
	pWriter->WriteAttributeString(NULL, NAME_ATTRIBUTE, NULL, dns);

	if (status) 
	{
		pWriter->WriteString(L"FAILED on DnsQuery");
	}
	else
	{
		if(pDnsRecord) 
		{
		   ipaddr.S_un.S_addr = (pDnsRecord->Data.A.IpAddress);
		   swprintf_s(buf, MAX_PATH - 1, L"%hs",inet_ntoa(ipaddr));
		   pWriter->WriteString(buf);
		}
	}

	SecureZeroMemory(buf, sizeof(buf));

	if(pDnsRecord)
		DnsRecordListFree(pDnsRecord, DnsFreeRecordListDeep);

	pDnsRecord = NULL;

	pWriter->WriteEndElement(); //end Query
	pWriter->Flush();
}

/*
Outputs XML elements based on antivirus DAT information.
*/
void OutputMcAfeeVSEDATInformation(IXmlWriter *pWriter)
{
	BOOL useWow6432Node = IsWow64();

	LPCWSTR regPath = useWow6432Node ? AVENGINE_64_REG_PATH : AVENGINE_32_REG_PATH;

    OutputRegistryString(HKEY_LOCAL_MACHINE, regPath, AVDAT_DATE_REG_NAME, DATE_ELEMENT, pWriter); 	// yyyy/MM/dd format

	OutputRegistryDWORD(HKEY_LOCAL_MACHINE, regPath, AVDAT_VERSION_REG_NAME, DAT_VER_MAJ_ELEMENT, pWriter);

	OutputRegistryDWORD(HKEY_LOCAL_MACHINE, regPath, AVDAT_VERSION_MINOR_REG_NAME, DAT_VER_MIN_ELEMENT, pWriter);

	pWriter->Flush();
}


/*
Outputs XML elements based on antivirus engine and product version information.
*/
void OutputMcAfeeVSEVersionInformation(IXmlWriter *pWriter)
{
	BOOL useWow6432Node = IsWow64();

	LPCWSTR regPath = useWow6432Node ? AVENGINE_64_REG_PATH  : AVENGINE_32_REG_PATH ;

    OutputRegistryDWORD(HKEY_LOCAL_MACHINE, regPath, AVENGINE_MAJOR_REG_NAME, AV_VER_MAJ_ELEMENT , pWriter);

	OutputRegistryDWORD(HKEY_LOCAL_MACHINE, regPath, AVENGINE_MINOR_REG_NAME, AV_VER_MIN_ELEMENT, pWriter);

	regPath = useWow6432Node ? SYSTEM_CORE_64_REG_PATH : SYSTEM_CORE_32_REG_PATH;

	OutputRegistryString(HKEY_LOCAL_MACHINE, regPath, SYSTEM_CORE_REG_NAME, CORE_VER_ELEMENT, pWriter);

	regPath = useWow6432Node ? DESKTOP_PROTECTION_64_REG_PATH : DESKTOP_PROTECTION_32_REG_PATH;

	OutputRegistryString(HKEY_LOCAL_MACHINE, regPath, PRODUCT_VERSION_REG_NAME, PRODUCT_ELEMENT, pWriter);

	pWriter->Flush();
}

/*
Outputs XML elements based on McAfee Global Threat Intelligence, aka Artemis, enable status and configuration level information.
*/
void OutputMcAfeeVSEArtemisComponent(LPCWSTR componentName, LPCWSTR path, IXmlWriter *pWriter)
{
	pWriter->WriteStartElement(NULL, COMPONENT_ELEMENT, NULL);
	pWriter->WriteAttributeString(NULL, NAME_ATTRIBUTE, NULL, componentName);

	OutputRegistryDWORD(HKEY_LOCAL_MACHINE, path, ARTEMIS_ENABLED_REG_NAME, ENABLED_ELEMENT, pWriter);
    OutputRegistryDWORD(HKEY_LOCAL_MACHINE, path, ARTEMIS_LEVEL_REG_NAME, LEVEL_ELEMENT, pWriter);

	pWriter->WriteEndElement(); //end Component
	pWriter->Flush();

}

/*
Outputs XML elements based on McAfee Global Threat Intelligence, aka Artemis, information for each McAfee component that may be able to have GTI configuration.
*/
void OutputMcAfeeVSEArtemis(IXmlWriter *pWriter)
{
	BOOL useWow6432Node = IsWow64();

	LPCWSTR regPath = useWow6432Node ? TASKS_64_REG_PATH : TASKS_32_REG_PATH;

    OutputMcAfeeVSEArtemisComponent(DP_COMPONENT, regPath, pWriter);

	regPath = useWow6432Node ? EMAIL_SCANNER_64_REG_PATH : EMAIL_SCANNER_32_REG_PATH;

    OutputMcAfeeVSEArtemisComponent(ES_COMPONENT, regPath, pWriter);

	regPath = useWow6432Node ? OUTLOOK_OPTIONS_64_REG_PATH :  OUTLOOK_OPTIONS_32_REG_PATH;

    OutputMcAfeeVSEArtemisComponent(OUTLOOK_COMPONENT, regPath, pWriter);

	regPath = useWow6432Node ? SCANNER_64_REG_PATH : SCANNER_32_REG_PATH;

	OutputMcAfeeVSEArtemisComponent(OAS_COMPONENT, regPath, pWriter);
}

/*
Outputs XML elements based on McAfee antivirus information.
*/
void OutputAntiVirus(IXmlWriter *pWriter)
{
	BOOL installed = FALSE;

	pWriter->WriteStartElement(NULL, AV_ROOT_ELEMENT, NULL);

	pWriter->WriteStartElement(NULL, MCAFEE_ELEMENT, NULL);

	installed = IsMcAfeeVSEInstalled();

	if(installed == TRUE) 
	{
		pWriter->WriteAttributeString(NULL, INSTALLED_ATTRIBUTE, NULL, L"true");

		pWriter->WriteStartElement(NULL, ARTEMIS_ELEMENT, NULL);

		__try 
		{
			pWriter->WriteStartElement(NULL, DNS_ELEMENT, NULL);
			OutputDnsQuery(AVTS_DNS_NAME, pWriter); //McAfee KB53733 
			OutputDnsQuery(AVQS_DNS_NAME, pWriter); //McAfee KB53735
			pWriter->WriteEndElement(); //end DNS
			pWriter->Flush();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			WCHAR buf[MAX_PATH] = {0};
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: OutputDnsQuery threw exception 0x%08x", GetExceptionCode());
			pWriter->WriteComment(buf);
			pWriter->Flush();
			SecureZeroMemory(buf, sizeof(buf));
		}

		__try 
		{
			OutputMcAfeeVSEArtemis(pWriter);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			WCHAR buf[MAX_PATH] = {0};
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: OutputMcAfeeVSEArtemis threw exception 0x%08x", GetExceptionCode());
			pWriter->WriteComment(buf);
			pWriter->Flush();
			SecureZeroMemory(buf, sizeof(buf));
		}

		pWriter->WriteEndElement(); //end Artemis
		pWriter->Flush();

		__try 
		{
			OutputServiceInformation(VSE_SERVICE_NAME, pWriter);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			WCHAR buf[MAX_PATH] = {0};
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: OutputServiceInformation threw exception 0x%08x", GetExceptionCode());
			pWriter->WriteComment(buf);
			pWriter->Flush();
			SecureZeroMemory(buf, sizeof(buf));
		}

		pWriter->WriteStartElement(NULL, DAT_ELEMENT, NULL);

		__try 
		{
			OutputMcAfeeVSEDATInformation(pWriter);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			WCHAR buf[MAX_PATH] = {0};
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: OutputMcAfeeVSEDATInformation threw exception 0x%08x", GetExceptionCode());
			pWriter->WriteComment(buf);
			pWriter->Flush();
			SecureZeroMemory(buf, sizeof(buf));
		}

		pWriter->WriteEndElement(); //end DAT
		pWriter->Flush();

		pWriter->WriteStartElement(NULL, VER_ELEMENT, NULL);

		__try {
			OutputMcAfeeVSEVersionInformation(pWriter);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			WCHAR buf[MAX_PATH] = {0};
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: OutputMcAfeeVSEVersionInformation threw exception 0x%08x", GetExceptionCode());
			pWriter->WriteComment(buf);
			pWriter->Flush();
			SecureZeroMemory(buf, sizeof(buf));
		}

		pWriter->WriteEndElement(); //end Version
		pWriter->Flush();
	}
	else 
	{
		pWriter->WriteAttributeString(NULL, INSTALLED_ATTRIBUTE, NULL, L"false");
	}

	pWriter->WriteEndElement(); //end McAfeeVSE
	pWriter->WriteEndElement(); //end LL_AV
	pWriter->Flush();
}

int _tmain(int argc, _TCHAR* argv[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	// only Vista and later support HeapEnableTerminationOnCorruption so don't bother checking the return value
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	HRESULT hres;

	IStream *pOutFileStream = NULL;
	IXmlWriter *pWriter = NULL;

	pOutFileStream = new FileStream(GetStdHandle(STD_OUTPUT_HANDLE));
	if (!pOutFileStream)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
		goto DONE;
	}

	hres = CreateXmlWriter(__uuidof(IXmlWriter), (void**)&pWriter, NULL);

	if (FAILED(hres))
		goto DONE;

	hres = pWriter->SetOutput(pOutFileStream);

	if (FAILED(hres))
		goto DONE;

	hres = pWriter->SetProperty(XmlWriterProperty_Indent, TRUE);

	if (FAILED(hres))
		goto DONE;

	hres = pWriter->SetProperty(XmlWriterProperty_OmitXmlDeclaration, FALSE);

	if (FAILED(hres))
		goto DONE;

	hres = pWriter->WriteStartDocument(XmlStandalone_Omit);

	if (FAILED(hres))
		goto DONE;

	OutputAntiVirus(pWriter);

	hres = S_OK;

DONE:

	if(pWriter)
		pWriter->WriteEndDocument();

	if(pWriter)
		pWriter->Flush();

	if (pOutFileStream)
		pOutFileStream->Release(); 

	pOutFileStream = NULL;

    if (pWriter)
		pWriter->Release(); 

	pWriter = NULL;

	return (int)hres;
}
