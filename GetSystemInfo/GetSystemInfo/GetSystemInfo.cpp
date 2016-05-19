#include <windows.h>
#include <atlstr.h>
#include <comdef.h>
#include <WbemCli.h>
#include <xmllite.h>
#include <ole2.h>
#include <windns.h>
#include "banned.h"

#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

#define _SDL_BANNED_RECOMMENDED

#define HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) \
	: ((HRESULT)(((x)& 0x0000ffff) | (FACILITY_WIN32 << 16) | 0x80000000)))


#pragma warning(disable : 4127)  // conditional expression is constant
#define SAFE_RELEASE(I)         do { if (I){ I->Release(); } I = NULL; } while(0)


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


// This routine does a DNS query on the FQDN of this system
// to obtain its IPv4 address. Then it enumerates the adapters
// to find an adapter with that address. Once an adapter is
// identified, this routine obtains its IPv6 address (if any)
// and its MAC address.
HRESULT LookupMyDomainIpAddress(
	IWbemServices *pSvc,
	LPWSTR fqdn, 
	LPWSTR *ip4Address, 
	LPWSTR *ip6Address, 
	LPWSTR *macAddress 
	)
{

	DNS_STATUS status;
	PDNS_RECORD pDnsRecord = { 0 };
	LPWSTR tmpIp4Address = NULL;
	LPWSTR tmpIp6Address = NULL;
	LPWSTR tmpMacAddress = NULL;

	BSTR query = NULL;
	BSTR wql  = NULL;
	WCHAR buf[32] = { 0 };
	ULONG hl;
	PUCHAR phl = (PUCHAR)&hl;

	HRESULT hres = E_FAIL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	BOOL bFoundAdapter = FALSE;

	SecureZeroMemory(buf, 32);

	query = SysAllocString(L"SELECT * FROM Win32_NetworkAdapterConfiguration");

	if (!query)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	wql = SysAllocString(L"WQL");

	if (!wql)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	status = DnsQuery(
		fqdn,
		DNS_TYPE_A,
		DNS_QUERY_NO_LOCAL_NAME,
		NULL,
		&pDnsRecord,
		NULL
		);

	if (ERROR_SUCCESS != (DWORD)status)
	{
		status = DnsQuery(
			fqdn,
			DNS_TYPE_A,
			0,
			NULL,
			&pDnsRecord,
			NULL
			);
	}

	if (ERROR_SUCCESS != (DWORD)status)
		return HRESULT_FROM_WIN32((DWORD)status);


	// There could be multiple IP address results: pDnsRecord could
	// be a linked list. But we have no basis for choosing one IP
	// address over the next. So we'll use the first one.

	hl = ntohl(pDnsRecord->Data.A.IpAddress);
	swprintf_s(buf, 31, L"%d.%d.%d.%d", phl[3], phl[2], phl[1], phl[0]);
	tmpIp4Address = _wcsdup(buf);

	if(pDnsRecord)
		DnsRecordListFree(pDnsRecord, DnsFreeRecordListDeep);

	pDnsRecord = NULL;

	//
	// Now use WMI to find the adapter having that IP address. Read off
	// its MAC address and IPv6 address.
	//

	// Use the IWbemServices pointer to make requests of WMI

	hres = pSvc->ExecQuery(
		wql,
		query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
		goto DONE;

	// Enumerate the adapters
	while (pEnumerator)
	{
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (!SUCCEEDED(hres)) goto DONE;

		if (!uReturn)
			break;

		VARIANT vtProp;
		VariantInit(&vtProp);


		SAFEARRAY *saIpAddresses;
		LONG lBound, uBound;
		LONG numElts;
		LPWSTR *pIpAddresses;

		hres = pclsObj->Get(L"IPAddress", 0, &vtProp, 0, 0);

		if (FAILED(hres))
		{
			pclsObj->Release();
			continue;
		}

#define CLEAR_RELEASE_CONT \
		{\
		VariantClear(&vtProp);\
		pclsObj->Release();\
		pclsObj = NULL;\
		continue;\
		}

		// Now to extract the array of IP addressess from the painful
		// COM VARIANT/SAFEARRAY wrapping. Continue if the array is
		// empty, that is the adapter has no IP addresses.

		if(VT_NULL == vtProp.vt) {
			continue;
		} else {
			saIpAddresses = vtProp.parray;

			if (!saIpAddresses)
				CLEAR_RELEASE_CONT;

			hres = SafeArrayGetLBound(saIpAddresses, 1, &lBound);

			if (FAILED(hres))
				CLEAR_RELEASE_CONT;

			hres = SafeArrayGetUBound(saIpAddresses, 1, &uBound);

			if (FAILED(hres))
				CLEAR_RELEASE_CONT;

			numElts = uBound - lBound + 1;

			if (numElts == 0)
				CLEAR_RELEASE_CONT;

			hres = SafeArrayAccessData(saIpAddresses, (void **)&pIpAddresses);

			if (FAILED(hres))
				CLEAR_RELEASE_CONT;

			// See if this adapter has our Ipv4 address
			for (LONG i = 0; i < numElts; i++)
			{
				if (0 == wcscmp(tmpIp4Address, (pIpAddresses[i])))
					bFoundAdapter = TRUE;
			}

			if (!bFoundAdapter)
				CLEAR_RELEASE_CONT;

			// See if found adapter has an IPv6 address.

			for (LONG i = 0; i < numElts; i++)
			{
				// if it has a colon, it's an IPv6 address
				if (NULL != wcschr(pIpAddresses[i], L':'))
				{
					tmpIp6Address = _wcsdup(pIpAddresses[i]);
					break;
				}
			}
			SafeArrayUnaccessData(saIpAddresses);
			VariantClear(&vtProp);
		}

		// Get the MAC address if required.
		if (macAddress)
		{
			hres = pclsObj->Get(L"MACAddress", 0, &vtProp, 0, 0);

			if (SUCCEEDED(hres))
			{
				if (VT_BSTR == vtProp.vt)
					tmpMacAddress = _wcsdup(vtProp.bstrVal);

				VariantClear(&vtProp);
			}
		}
		pclsObj->Release();
		pclsObj = NULL;

		// If we get here, we've found the adapter.
		break;


	} // end while (pEnumerator)


	if (bFoundAdapter)
	{
		hres = S_OK;
		if (ip4Address) 
			*ip4Address = tmpIp4Address;

		if (ip6Address) 
			*ip6Address = tmpIp6Address;

		if (macAddress) 
			*macAddress = tmpMacAddress;
	}
	else
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
	}


DONE:

	if (FAILED(hres))
	{
		if (tmpIp4Address) 
			free(tmpIp4Address);

		if (tmpIp6Address) 
			free(tmpIp6Address);

		if (tmpMacAddress) 
			free(tmpMacAddress);
	}

	if (pEnumerator)
		pEnumerator->Release();

	if (wql)
		SysFreeString(wql);

	if (query)
		SysFreeString(query);

	return hres;
}

HRESULT GetOSInformation(
	IWbemServices *pSvc,
	LPWSTR *osName,
	LPWSTR *osVersion,
	DWORD *servicePack,
	DWORD *productType
	)
{
	LPWSTR tmpOSName = NULL;
	LPWSTR tmpOtherTypeDescription = NULL;
	LPWSTR tmpOSVersion = NULL;
	DWORD tmpServicePack = 0;
	DWORD tmpProductType = 0;

	BSTR query = NULL;
	BSTR wql = NULL;
	WCHAR nameBuf[MAX_PATH] = { 0 };
	WCHAR versionBuf[MAX_PATH] = { 0 };
	HRESULT hres = E_FAIL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	size_t ret = 0;

	query = SysAllocString(L"SELECT Caption,OtherTypeDescription,Version,ServicePackMajorVersion,ProductType FROM Win32_OperatingSystem WHERE Primary=TRUE");

	if (!query)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	wql = SysAllocString(L"WQL");

	if (!wql)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	hres = pSvc->ExecQuery(
		wql,
		query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
		goto DONE;

	while (pEnumerator)
	{
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (!SUCCEEDED(hres))
			goto DONE;

		if (!uReturn)
			break;

		VARIANT vtProp;
		VariantInit(&vtProp);

		hres = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hres))
		{
			if(VT_BSTR == vtProp.vt) {
				tmpOSName = (wchar_t*)_bstr_t(vtProp.bstrVal);

				CString os(tmpOSName);
				os.Trim();
				os.Remove((wchar_t)0x00A9); //C = copyright
				os.Remove((wchar_t)0x00AE); //R = registered
				os.Remove((wchar_t)0x2122); //TM = trademark
				os.Replace(L"(TM)", L"");
				os.Replace(L"(R)", L""); // used on Windows XP X64

				ret = wcscat_s(nameBuf, MAX_PATH - 1, os.GetBuffer());
			}
		}

		VariantClear(&vtProp);

		VariantInit(&vtProp);

		hres = pclsObj->Get(L"OtherTypeDescription", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hres))
		{
			if(VT_BSTR == vtProp.vt) {
				ret = wcscat_s(nameBuf, MAX_PATH - 1, L" ");
				tmpOtherTypeDescription = (wchar_t*)_bstr_t(vtProp.bstrVal);
				ret = wcscat_s(nameBuf, MAX_PATH - 1, tmpOtherTypeDescription);
			}
		}

		if(osName)
			*osName = nameBuf;

		VariantClear(&vtProp);

		VariantInit(&vtProp);

		hres = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hres))
		{
			if(VT_BSTR == vtProp.vt) {
				tmpOSVersion = (wchar_t*)_bstr_t(vtProp.bstrVal);

				CString os(tmpOSVersion);
				os.Trim();

				ret = wcscat_s(versionBuf, MAX_PATH - 1, os.GetBuffer());
			}
		}

		if(osVersion)
			*osVersion = versionBuf;

		VariantClear(&vtProp);		

		VariantInit(&vtProp);

		hres = pclsObj->Get(L"ServicePackMajorVersion", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hres))
		{
			if(VT_I4 == vtProp.vt) // Win32_OperatingSystem.ServicePackMajorVersion property is documented as a uint16 but https://msdn.microsoft.com/en-us/library/aa392716(v=vs.85).aspx says COMS returns it as VT_I4 instead of VT_I2
			{
				tmpServicePack = (DWORD)vtProp.ulVal;
			}
		}

		*servicePack = tmpServicePack;

		VariantClear(&vtProp);

		VariantInit(&vtProp);

		hres = pclsObj->Get(L"ProductType", 0, &vtProp, 0, 0);

		if (SUCCEEDED(hres))
		{
			if(VT_I4 == vtProp.vt) // Win32_OperatingSystem.ProductType property is documented as a uint32 but https://msdn.microsoft.com/en-us/library/aa392716(v=vs.85).aspx says COMS returns it as VT_I4 instead of VT_UI4
			{
				tmpProductType = (DWORD)vtProp.ulVal;
			}
		}

		VariantClear(&vtProp);

		*productType = tmpProductType;

		pclsObj->Release();
		pclsObj = NULL;
	}


DONE:

	if (FAILED(hres))
	{
		if (tmpOSName)
			free(tmpOSName);

		if (tmpOtherTypeDescription)
			free(tmpOtherTypeDescription);

		if(tmpOSVersion)
			free(tmpOSVersion);
	}

	if (pEnumerator)
		pEnumerator->Release();

	if (wql)
		SysFreeString(wql);

	if (query)
		SysFreeString(query);

	return hres;
}



HRESULT GetProcessorArchitecture(
	IWbemServices *pSvc,
	DWORD *architecture
	)
{
	DWORD tmpArchitecture = 0;

	BSTR query = NULL;
	BSTR wql = NULL;
	HRESULT hres;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;

	query = SysAllocString(L"SELECT AddressWidth,DataWidth,Architecture,ProcessorId FROM Win32_Processor WHERE DeviceID='CPU0'");

	if (!query)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	wql = SysAllocString(L"WQL");

	if (!wql)
	{
		hres = HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		goto DONE;
	}

	hres = pSvc->ExecQuery(
		wql,
		query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
		goto DONE;

	while (pEnumerator)
	{
		hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (!SUCCEEDED(hres)) goto DONE;

		if (!uReturn)
			break;

		VARIANT vtProp;
		VariantInit(&vtProp);

		hres = pclsObj->Get(L"Architecture", 0, &vtProp, 0, 0); 

		if (FAILED(hres))
		{
			pclsObj->Release();
			continue;
		}

		if(VT_I4 == vtProp.vt) { // Win32_Processor.Architecture property is documented as a uint16 but https://msdn.microsoft.com/en-us/library/aa392716(v=vs.85).aspx says COMS returns it as VT_I4 instead of VT_I2
			tmpArchitecture = (DWORD)vtProp.ulVal;
		}

		VariantClear(&vtProp);

		if(architecture)
			*architecture = tmpArchitecture;

		pclsObj->Release();
		pclsObj = NULL;
	}


DONE:

	if (pEnumerator)
		pEnumerator->Release();

	if (wql)
		SysFreeString(wql);

	if (query)
		SysFreeString(query);

	return hres;
}

// Outputs
//	<systemInfo>
//		<hostname>...</hostName>
//		<domainName>...</domainName>
//		<ip4Address>...</ip4Address>
//		<ip6Address>...</ip6Address>
//		<macAddress>...</macAddress>
//		<timeStamp>...</timeStamp>
//		<osName>...</osName>
//		<osVersion>6.1</osVersion>
//		<servicePack>0</servicePack>
//		<productType>...</productType>
//		<osArch>...</osArch>
//		<hardArch>...</hardArch>
//	</systemInfo>
//

VOID OutputSystemInfo(
	IWbemServices *pSvc,
	IXmlWriter *pWriter
	)
{
	WCHAR tmpHostName[MAX_PATH] = { 0 };
	WCHAR tmpDomain[MAX_PATH] = { 0 };
	WCHAR fqdn[MAX_PATH] = { 0 };
	WCHAR buf[MAX_PATH] = { 0 };
	DWORD size = MAX_PATH - 1;
	BOOL bRet;

	HRESULT hres;
	LPWSTR tmpIp4Address = NULL;
	LPWSTR tmpIp6Address = NULL;
	LPWSTR tmpMacAddress = NULL;
	LPWSTR toWrite;
	//OSVERSIONINFOEX vi = { 0 };
	SYSTEMTIME st = { 0 };
	SYSTEM_INFO si = { 0 };

	pWriter->WriteStartElement(NULL, L"systemInfo", NULL);

	// Get host name
	bRet = GetComputerNameEx(ComputerNameDnsHostname, tmpHostName, &size);

	if (!bRet)
	{
		swprintf_s(buf, MAX_PATH - 1, L"ERROR: GetComputerNameEx, error %d", GetLastError());
		pWriter->WriteComment(buf);
	}

	pWriter->WriteElementString(NULL, L"hostName", NULL, tmpHostName);
	pWriter->Flush();

	// Get the fully qualified domain name
	size = MAX_PATH - 1;

	bRet = GetComputerNameEx(ComputerNameDnsDomain, tmpDomain, &size);

	if (!bRet)
	{
		swprintf_s(buf, MAX_PATH - 1, L"ERROR: GetComputerNameEx, error %d", GetLastError());
		pWriter->WriteComment(buf);
	}

	pWriter->WriteElementString(NULL, L"domainName", NULL, tmpDomain);
	pWriter->Flush();

	// Get IP addresses and MAC

	size = MAX_PATH - 1;
	bRet = GetComputerNameEx(ComputerNameDnsFullyQualified, fqdn, &size);

	if (bRet)
	{
		hres = LookupMyDomainIpAddress(pSvc, fqdn, &tmpIp4Address, &tmpIp6Address, &tmpMacAddress);

		if (FAILED(hres))
		{
			swprintf_s(buf, MAX_PATH - 1, L"ERROR: LookupMyDomainIpAddress, error %d, HR 0x%08x", GetLastError(), hres);
			pWriter->WriteComment(buf);
		}
	}

	toWrite = (tmpIp4Address ? tmpIp4Address : L"");
	pWriter->WriteElementString(NULL, L"ip4Address", NULL, toWrite);

	toWrite = (tmpIp6Address ? tmpIp6Address : L"");
	pWriter->WriteElementString(NULL, L"ip6Address", NULL, toWrite);

	toWrite = (tmpMacAddress ? tmpMacAddress : L"");
	pWriter->WriteElementString(NULL, L"macAddress", NULL, toWrite);
	pWriter->Flush();

	GetLocalTime(&st);

	SecureZeroMemory(buf, sizeof(buf));

	swprintf_s(buf, MAX_PATH - 1, L"%04d%02d%02d%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	pWriter->WriteElementString(NULL, L"timeStamp", NULL, buf);
	pWriter->Flush();

	SecureZeroMemory(buf, sizeof(buf));

	LPWSTR osName = NULL;
	LPWSTR osVersion = NULL;
	DWORD servicePack = 0;
	DWORD productType = 0;

	// Can't use GetVersionEx to get the OS version from Windows 8.1 on. Have to use the registry.
	// Can't use registry to get OS version from Windows 10 on. Have to use WMI.
	hres = GetOSInformation(pSvc, &osName, &osVersion, &servicePack, &productType);

	if (FAILED(hres))
	{
		swprintf_s(buf, MAX_PATH - 1, L"ERROR: GetOSInformation, error %d HR 0x%08x", GetLastError(), hres);
		pWriter->WriteComment(buf);
	}

	toWrite = (osName ? osName : L"");
	pWriter->WriteElementString(NULL, L"osName", NULL, toWrite);
	pWriter->Flush();

	toWrite = (osVersion ? osVersion : L"");
	pWriter->WriteElementString(NULL, L"osVersion", NULL, toWrite);
	pWriter->Flush();

	SecureZeroMemory(buf, sizeof(buf));

	swprintf_s(buf, MAX_PATH - 1, L"%d", servicePack);
	pWriter->WriteElementString(NULL, L"servicePack", NULL, buf);
	pWriter->Flush();

	SecureZeroMemory(buf, sizeof(buf));

	switch (productType)
	{
	case VER_NT_DOMAIN_CONTROLLER:
		wcscpy_s(buf, MAX_PATH - 1, L"domain controller");
		break;
	case VER_NT_SERVER:
		wcscpy_s(buf, MAX_PATH - 1, L"server");
		break;
	case VER_NT_WORKSTATION:
		wcscpy_s(buf, MAX_PATH - 1, L"workstation");
		break;
	}

	pWriter->WriteElementString(NULL, L"productType", NULL, buf);
	pWriter->Flush();

	GetNativeSystemInfo(&si);

	SecureZeroMemory(buf, sizeof(buf));

	switch (si.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		wcscpy_s(buf, MAX_PATH - 1, L"x86");
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		wcscpy_s(buf, MAX_PATH - 1, L"x64");
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		wcscpy_s(buf, MAX_PATH - 1, L"Itanium");
		break;
	}

	pWriter->WriteElementString(NULL, L"osArch", NULL, buf);
	pWriter->Flush();

	DWORD processorArchitecture = 0;

	hres = GetProcessorArchitecture(pSvc, &processorArchitecture);

	SecureZeroMemory(buf, sizeof(buf));

	if (FAILED(hres))
	{
		swprintf_s(buf, MAX_PATH - 1, L"ERROR: GetProcessorArchitecture, error %d HR 0x%08x", GetLastError(), hres);
		pWriter->WriteComment(buf);
	}

	SecureZeroMemory(buf, sizeof(buf));

	switch (processorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		wcscpy_s(buf, MAX_PATH - 1, L"x86");
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		wcscpy_s(buf, MAX_PATH - 1, L"x64");
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		wcscpy_s(buf, MAX_PATH - 1, L"Itanium");
		break;
	}

	pWriter->WriteElementString(NULL, L"hardArch", NULL, buf);
	pWriter->Flush();


	pWriter->WriteEndElement();
	pWriter->Flush();


	if (tmpIp4Address)
		free(tmpIp4Address);

	if (tmpIp6Address)
		free(tmpIp6Address);

	if (tmpMacAddress)
		free(tmpMacAddress);
}


int _tmain(int argc, _TCHAR* argv[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	HRESULT hres;
	IWbemLocator *pLoc = NULL;
	IWbemServices *pSvc = NULL;

	IStream *pOutFileStream = NULL;
	IXmlWriter *pWriter = NULL;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) return hres;

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
		);

	if (FAILED(hres))
		goto DONE;


	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *)&pLoc);

	if (FAILED(hres))
		goto DONE;


	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (e.g. Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
		);

	if (FAILED(hres))
		goto DONE;


	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
		);

	if (FAILED(hres))
		goto DONE;

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

	OutputSystemInfo(pSvc, pWriter);

	hres = S_OK;

DONE:

	if(pWriter)
		pWriter->WriteEndDocument();

	if (pWriter)
		pWriter->Flush();

	SAFE_RELEASE(pOutFileStream);
	SAFE_RELEASE(pWriter);

	if (pSvc)
		pSvc->Release();

	if (pLoc)
		pLoc->Release();

	CoUninitialize();

	return (int)hres;
}