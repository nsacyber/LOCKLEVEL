#include <Windows.h>
#include <iostream>

#include <sddl.h>
#include <Iads.h>
#include <AdsHlp.h>
#include <ActiveDS.h>
#include <atlconv.h>


//#include <winevt.h>

#include <exception>
#include <vector>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <stack>
#include <iterator>
#include <algorithm>
#include <map>
#include <string>

using namespace std;

typedef HANDLE EVT_HANDLE, *PEVT_HANDLE;

typedef struct _EVT_VARIANT
{
	union
	{
		BOOL        BooleanVal;
		INT8        SByteVal;
		INT16       Int16Val;
		INT32       Int32Val;
		INT64       Int64Val;
		UINT8       ByteVal;
		UINT16      UInt16Val;
		UINT32      UInt32Val;
		UINT64      UInt64Val;
		float       SingleVal;
		double      DoubleVal;
		ULONGLONG   FileTimeVal;
		SYSTEMTIME* SysTimeVal;
		GUID*       GuidVal;
		LPCWSTR     StringVal;
		LPCSTR      AnsiStringVal;
		PBYTE       BinaryVal;
		PSID        SidVal;
		size_t      SizeTVal;

		// array fields
		BOOL*       BooleanArr;
		INT8*       SByteArr;
		INT16*      Int16Arr;
		INT32*      Int32Arr;
		INT64*      Int64Arr;
		UINT8*      ByteArr;
		UINT16*     UInt16Arr;
		UINT32*     UInt32Arr;
		UINT64*     UInt64Arr;
		float*      SingleArr;
		double*     DoubleArr;
		FILETIME*   FileTimeArr;
		SYSTEMTIME* SysTimeArr;
		GUID*       GuidArr;
		LPWSTR*     StringArr;
		LPSTR*      AnsiStringArr;
		PSID*       SidArr;
		size_t*     SizeTArr;

		// internal fields
		EVT_HANDLE  EvtHandleVal;
		LPCWSTR     XmlVal;
		LPCWSTR*    XmlValArr;
	};

	DWORD Count;   // number of elements (not length) in bytes.
	DWORD Type;

} EVT_VARIANT, *PEVT_VARIANT;

typedef enum _EVT_VARIANT_TYPE
{
	EvtVarTypeNull = 0,
	EvtVarTypeString = 1,
	EvtVarTypeAnsiString = 2,
	EvtVarTypeSByte = 3,
	EvtVarTypeByte = 4,
	EvtVarTypeInt16 = 5,
	EvtVarTypeUInt16 = 6,
	EvtVarTypeInt32 = 7,
	EvtVarTypeUInt32 = 8,
	EvtVarTypeInt64 = 9,
	EvtVarTypeUInt64 = 10,
	EvtVarTypeSingle = 11,
	EvtVarTypeDouble = 12,
	EvtVarTypeBoolean = 13,
	EvtVarTypeBinary = 14,
	EvtVarTypeGuid = 15,
	EvtVarTypeSizeT = 16,
	EvtVarTypeFileTime = 17,
	EvtVarTypeSysTime = 18,
	EvtVarTypeSid = 19,
	EvtVarTypeHexInt32 = 20,
	EvtVarTypeHexInt64 = 21,

	// these types used internally
	EvtVarTypeEvtHandle = 32,
	EvtVarTypeEvtXml = 35

} EVT_VARIANT_TYPE;

typedef enum _EVT_RENDER_CONTEXT_FLAGS
{
	EvtRenderContextValues = 0,         // Render specific properties
	EvtRenderContextSystem,             // Render all system properties (System)
	EvtRenderContextUser                // Render all user properties (User/EventData)

} EVT_RENDER_CONTEXT_FLAGS;

typedef enum _EVT_RENDER_FLAGS
{
	EvtRenderEventValues = 0,           // Variants
	EvtRenderEventXml,                  // XML
	EvtRenderBookmark                   // Bookmark

} EVT_RENDER_FLAGS;

typedef enum _EVT_OPEN_LOG_FLAGS
{
	EvtOpenChannelPath = 0x1,
	EvtOpenFilePath = 0x2

} EVT_OPEN_LOG_FLAGS;

typedef BOOL(WINAPI *evtRender_t)(EVT_HANDLE, EVT_HANDLE, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef EVT_HANDLE(WINAPI *evtCreateRenderContext_t)(DWORD, LPCWSTR*, DWORD);
typedef BOOL(WINAPI *evtNext_t)(EVT_HANDLE, DWORD, EVT_HANDLE*, DWORD, DWORD, PDWORD);
typedef BOOL(WINAPI *evtClose_t)(EVT_HANDLE);
typedef EVT_HANDLE(WINAPI *evtQuery_t)(EVT_HANDLE, LPCWSTR, LPCWSTR, DWORD);

evtRender_t EvtRender;
evtCreateRenderContext_t EvtCreateRenderContext;
evtNext_t EvtNext;
evtClose_t EvtClose;
evtQuery_t EvtQuery;

class RootDseFailure : public runtime_error {
public:
	RootDseFailure() : runtime_error("RootDseFailure") {}
};

class EventLogFailure : public runtime_error {
public:
	EventLogFailure() : runtime_error("EventLogFailure") {}
};

class EventRenderFailure : public runtime_error {
public:
	EventRenderFailure() : runtime_error("EventRenderFailure") {}
};

class AdminGroupFailure : public runtime_error {
public:
	AdminGroupFailure() : runtime_error("AdminGroupFailure") {}
};

class ADSQueryFailure : public runtime_error {
public:
	ADSQueryFailure() : runtime_error("ADSQueryFailure") {}
};

class AccountNameFailure : public runtime_error {
public:
	AccountNameFailure() : runtime_error("AccountNameFailure") {}
};



const enum LOGON_TYPE : DWORD {NETWORK_LOGON=3};

wstring GetLDAPContext() {
	IADs *pads = NULL;
	VARIANT var;
	HRESULT hr = S_OK;
	wstring result;

	hr = ADsGetObject(L"LDAP://rootDse", IID_IADs, (void**)&pads);
	if (FAILED(hr)) {
		throw RootDseFailure();
	}

	VariantInit(&var);
	hr = pads->Get(BSTR(L"defaultNamingContext"), &var);
	if (FAILED(hr)) {
		pads->Release();
		throw RootDseFailure();
	}

	result = wstring((const wchar_t*) var.bstrVal);

	if (pads) pads->Release();
	VariantClear(&var);

	return result;
}

wstring DomainAdminGroupQuery(wstring context, wstring adminGroup) {
	return L"LDAP://CN=" + adminGroup + L",CN=Users," + context;
}

set<wstring> GetMemberQueries(IADsMembers *pMembers) {
	HRESULT hr = S_OK;
	IUnknown *pUnk = NULL;
	IEnumVARIANT *pEnum = NULL;
	IDispatch *pDisp = NULL;
	IADs *pADs = NULL;
	BSTR bstr = NULL;
	VARIANT var;
	ULONG lFetch = 0;
	set<wstring> queries = set<wstring>();
	hr = pMembers->get__NewEnum(&pUnk);
	if (FAILED(hr)) {
		goto cleanup;
	}
	hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
	if (FAILED(hr)) {
		goto cleanup;
	}

	hr = pEnum->Next(1, &var, &lFetch);
	if (FAILED(hr)) {
		goto cleanup;
	}

	while (hr == S_OK) {
		if (lFetch == 1) {
			pDisp = V_DISPATCH(&var);
			hr = pDisp->QueryInterface(IID_IADs, (void**)&pADs);
			if (FAILED(hr)) {
				goto cleanup;
			}
			
			hr = pADs->get_ADsPath(&bstr);
			if (FAILED(hr)) {
				goto cleanup;
			}
			queries.insert(wstring((const wchar_t*)bstr));
			SysFreeString(bstr);
		}
		VariantClear(&var);
		pDisp = NULL;
		hr = pEnum->Next(1, &var, &lFetch);
	}

cleanup:
	if (pUnk){
		pUnk->Release();
	}
		
	if (pEnum){
		pEnum->Release();
	}
	if (pDisp){
		pDisp->Release();
	}
		
	if (pADs){
		pADs->Release();
	}

	VariantClear(&var);

	if (FAILED(hr)){
		throw AdminGroupFailure();
	}
		

	return queries;
}

void PrintSet(set<wstring> s, wstring prefix) {
	set<wstring>::iterator it;
	for (it = s.begin(); it != s.end(); ++it) {
		wcout << prefix.c_str() << (*it).c_str() << L"\r\n";
	}
}

void PrintSet(set<wstring> s) {
	PrintSet(s, L"");
}

wstring GetAdministratorsQuery(void){
	return L"LDAP://CN=Administrators, CN=Builtin," + GetLDAPContext();
}

BOOL isExpectedIADsClass(IADs *actual, BSTR expectedClass){
	BSTR actualClass = NULL;
	actual->get_Class(&actualClass);
	BOOL isExpected =  wcscmp(actualClass, expectedClass) == 0;
	
	SysFreeString(actualClass);
	actualClass = NULL;

	return isExpected;
	

}

wstring QuerySid(wstring query) {
	IADs *pAD = NULL;
	VARIANT var;
	HRESULT hr = S_OK;
	wstring result;
	LPWSTR sid;

	hr = ADsGetObject(query.c_str(), IID_IADs, (void**)&pAD);
	if (FAILED(hr)) {
		goto cleanup;
	}

	VariantInit(&var);
	hr = pAD->Get(BSTR(L"objectSid"), &var);
	if (FAILED(hr)) {
		goto cleanup;
	}

	if (!ConvertSidToStringSidW((PSID)var.parray->pvData, &sid)) {
		hr = E_FAIL;
		goto cleanup;
	}

	result = wstring((const wchar_t*)sid);
	LocalFree(sid);

	

cleanup:

	VariantClear(&var);
	if (pAD)
		pAD->Release();

	if (FAILED(hr))
		throw ADSQueryFailure();

	return result;
}

#define MAX_GROUP_LEN 64
#define MAX_NAME 256

wstring ConvertStringSidToAccountName(wstring sid) {
	PSID pSid = NULL;
	WCHAR name[MAX_GROUP_LEN];
	DWORD nameSize = MAX_GROUP_LEN;
	WCHAR domain[MAX_NAME];
	DWORD domainSize = MAX_NAME;
	SID_NAME_USE nameUse;
	DWORD err = ERROR_SUCCESS;

	if (!ConvertStringSidToSidW(sid.c_str(), &pSid)) {
		err = GetLastError();
		goto cleanup;
	}

	if (!LookupAccountSidW(NULL, pSid, name, &nameSize, domain, &domainSize, &nameUse)) {
		err = GetLastError();
		goto cleanup;
	}

cleanup:
	if (pSid)
		LocalFree(pSid);

	if (err != ERROR_SUCCESS)
		throw AccountNameFailure();

	return wstring(name);
}

wstring DomainAdminsGroupName() {
	wstring context = GetLDAPContext();
	wstring domainSid = QuerySid(L"LDAP://" + context);
	wstring domainAdminSid = domainSid + L"-512";

	return ConvertStringSidToAccountName(domainAdminSid);
}

HRESULT GetMembers(IADsGroup *pGroup, unordered_set<wstring>& members){
	//from https://msdn.microsoft.com/en-us/library/aa706042(v=vs.85).aspx
	IUnknown *pUnk = NULL;
	IADs *pcurrentIads = NULL;
	IADsMembers *pMembers = NULL;
	IDispatch *pDisp = NULL;
	BSTR adsPath = NULL;
	VARIANT var;
	HRESULT hr = S_OK;



	ULONG lFetch;
	

	
	hr = pGroup->Members(&pMembers);
	if (FAILED(hr)){
		goto CLEANUP;
	}


	hr = pMembers->get__NewEnum(&pUnk);
	if (FAILED(hr)){
		goto CLEANUP;
	}

	IEnumVARIANT *pEnum;
	hr = pUnk->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
	if (FAILED(hr)){
		goto CLEANUP;
	}



	VariantInit(&var);
	hr = pEnum->Next(1, &var, &lFetch);
	if (FAILED(hr)){
		goto CLEANUP;
	}

	while (hr == S_OK){
		if (1 == lFetch){
			pDisp = V_DISPATCH(&var);
			hr = pDisp->QueryInterface(IID_IADs, (void**)&pcurrentIads);
			if (FAILED(hr)){
				goto CLEANUP;
			}
			
			if (pcurrentIads && 
				SUCCEEDED(pcurrentIads->get_ADsPath(&adsPath))){
				
				members.insert(wstring{ (WCHAR*)adsPath });
			}
			SysFreeString(adsPath);
			adsPath = NULL; 

			
		}

		VariantClear(&var);
		pDisp = NULL;
		hr = pEnum->Next(1, &var, &lFetch);
		if (FAILED(hr)){
			goto CLEANUP;
		}
	}



CLEANUP:
	if (pUnk){
		pUnk->Release();
	}
	if (pcurrentIads){
		pcurrentIads->Release();
	}
	if (pDisp){
		pDisp->Release();
	}
	if (pMembers){
		pMembers->Release();
	}
	
	if (adsPath){
		SysFreeString(adsPath);
	}
	
	VariantClear(&var);
	return hr;




}

unordered_set<wstring> filterIADsInfoByClass(unordered_set<wstring> iadsInfo, set<wstring> includeFilter){
	HRESULT hr = S_OK;
	IADs *piads;

	unordered_set<wstring> filteredIadsInfo;
	for (auto it : iadsInfo){
		hr = ADsGetObject(
			it.c_str(),
			IID_IADs,
			(void**)&piads);
		if (FAILED(hr)){
			continue;
		}
		
		BSTR className = NULL;
		hr = piads->get_Class(&className);
		if (FAILED(hr)){
			continue;
		}
		
		wstring wstrClassName{ (WCHAR*)className };

		if (includeFilter.find(wstrClassName) != includeFilter.end()){
			filteredIadsInfo.insert(it);
		}
	}

	return filteredIadsInfo;
}

HRESULT GetGroups(IADsGroup *pGroup, set<wstring>& groups){
	HRESULT hr = S_OK;
	
	unordered_set<wstring> membersPaths{};

	hr = GetMembers(pGroup, membersPaths);
	if (FAILED(hr)){
		goto CLEANUP;
	}


	membersPaths = filterIADsInfoByClass(membersPaths, set<wstring>{L"group"});

	for (auto it : membersPaths){
		groups.insert(it);
	}

CLEANUP:

	return hr;
}


HRESULT GetUsers(IADsGroup *pGroup, unordered_set<wstring>& users){
	HRESULT hr = S_OK;

	unordered_set<wstring> memberInfo{};
	if (FAILED(hr)){
		goto CLEANUP;
	}

	
	hr = GetMembers(pGroup, memberInfo);
	if (FAILED(hr)){
		goto CLEANUP;
	}

	memberInfo = filterIADsInfoByClass(memberInfo, set<wstring>{L"user"});

	for (auto it : memberInfo){
		users.insert(it);
	}

CLEANUP:

	return hr;
}




unordered_set<wstring> GetMembers(IADsGroup *pGroup, BOOL recurse){
	HRESULT hr = S_OK;
	unordered_set<wstring> users{};
	unordered_set<wstring> groups{};
	unordered_set<wstring> members{};

	stack<wstring> groupsToProcess{};
	unordered_set<wstring> visited{};

	hr = GetMembers(pGroup, members);

	if (recurse){
		groups = filterIADsInfoByClass(members, set<wstring>{L"group"});

		for (auto it : groups){
			groupsToProcess.push(it);
		}


		while (!groupsToProcess.empty()){
			wstring currentGroup = groupsToProcess.top();
			groupsToProcess.pop();
			
			if (visited.find(currentGroup) == visited.end()){
				visited.insert(currentGroup);

				IADsGroup *nextGroup = NULL;

				hr = ADsGetObject(
					currentGroup.c_str(),
					IID_IADsGroup,
					(void**)&nextGroup);
				if (FAILED(hr)){
					goto CLEANUP;
				}

				hr = GetMembers(nextGroup, members);
				groups = filterIADsInfoByClass(members, set<wstring>{L"group"});
				if (FAILED(hr)){
					goto CLEANUP;
				}


				for (auto it : groups){
					groupsToProcess.push(it);
				}

			}

		}

	}

	



CLEANUP:
	


	return members;
}

unordered_set<wstring> GetUsers(IADsGroup *pGroup, BOOL recurse){
	return filterIADsInfoByClass(
		GetMembers(pGroup, recurse),
		set<wstring>{L"user"});
}

unordered_set<wstring> GetUsers(wstring groupDN, BOOL recurse){
	HRESULT hr = S_OK;
	IADsGroup *pGroup = NULL;

	unordered_set<wstring> users{};

	hr = ADsGetObject(
		groupDN.c_str(),
		IID_IADsGroup,
		(void**)&pGroup);

	if (FAILED(hr)){
		goto CLEANUP;
	}

	users = GetUsers(pGroup, recurse);


CLEANUP:
	if (pGroup){
		pGroup->Release();
	}


	return users;
}



wstring GetUserFilter(){
	return L"(&(objectCategory=person)(objectClass=user))";
}


LPOLESTR ConvertWstring2Olestr(wstring ws){
	LPOLESTR olestr = new OLECHAR[ws.size() + sizeof(WCHAR)];
	SecureZeroMemory(olestr, sizeof(olestr));

	swprintf_s(olestr, ws.size(), L"%s", ws.c_str());

	return olestr;

}

set<wstring> GetDomainAdministrators(){
	set<wstring> administrators{};

	for (auto it : GetUsers(GetAdministratorsQuery(), TRUE)){
		administrators.insert(QuerySid(it));
	}
	return administrators;

}


#define BATCH_SIZE 10

BOOL isNetworkLogonType(PEVT_VARIANT pEvt, DWORD propCount){
	if (NULL == pEvt || propCount != 2 || pEvt[1].Type != EvtVarTypeUInt32)
		throw EventRenderFailure();
	
	return pEvt[1].UInt32Val == NETWORK_LOGON;
		
	
}

wstring ExtractSid(PEVT_VARIANT pEvt, DWORD propCount) {
	if (propCount != 2 || pEvt[0].Type != EvtVarTypeSid)
		throw EventRenderFailure();
	LPWSTR sidStr = NULL;
	wstring wsid{};
	
	if (!ConvertSidToStringSidW(pEvt[0].SidVal, &sidStr)) {
		throw EventRenderFailure();
	}
	wsid = wstring(sidStr);
	LocalFree(sidStr);

	
		
	
	
	
	
	return wsid;
}

wstring GetSid(EVT_HANDLE hEvent, EVT_HANDLE renderContext) {
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	DWORD status = ERROR_SUCCESS;
	wstring sidStr;

	if (!EvtRender(renderContext, hEvent, EvtRenderEventValues, 0, NULL, &dwBufferUsed, &dwPropertyCount)) {
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError())) {
			dwBufferSize = dwBufferUsed;
			pRenderedValues = (PEVT_VARIANT) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
			try {
				if (EvtRender(renderContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
					if (!isNetworkLogonType(pRenderedValues, dwPropertyCount)){
						sidStr = ExtractSid(pRenderedValues, dwPropertyCount);
					}
					
				}
				HeapFree(GetProcessHeap(), 0, pRenderedValues);
				return sidStr;
			}
			catch (...) {
				HeapFree(GetProcessHeap(), 0, pRenderedValues);
				throw;
			}
		}
		throw EventRenderFailure();
	}
	throw EventRenderFailure();
}

/*
Caller must call EvtClose in the EVT_HANDLE when finished.
*/
EVT_HANDLE GetRenderContext() {
	LPWSTR ppValues[] = { L"Event/EventData/Data[@Name='TargetUserSid']", L"Event/EventData/Data[@Name='LogonType']" };
	DWORD count = sizeof(ppValues) / sizeof(LPWSTR);
	EVT_HANDLE hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
	if (NULL == hContext) {
		throw GetLastError();
	}
	return hContext;
}

BOOL isIn(set<wstring> s, wstring ele){
	return s.find(ele) != s.cend();
}

vector<wstring> GetLogonSids() {
	EVT_HANDLE evt = NULL;
	EVT_HANDLE hEvents[BATCH_SIZE];
	DWORD dwReturned = 0;
	vector<wstring> sids{};
	DWORD status = ERROR_SUCCESS;
	wstring sid;

	EVT_HANDLE sidRenderContext = GetRenderContext();

	evt = EvtQuery(NULL, L"Security", L"Event/System[EventID=4624]", EvtOpenChannelPath);

	if (NULL == evt) {
		EvtClose(sidRenderContext);
		throw EventLogFailure();
	}

	for(;;){
		if (!EvtNext(evt, BATCH_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
			if (ERROR_NO_MORE_ITEMS != (status = GetLastError())) {
				EvtClose(sidRenderContext);
				throw status;
			}
			status = ERROR_SUCCESS;
			goto cleanup;
		}

		for (DWORD i = 0; i < dwReturned; i++) {
			try {
				sid = GetSid(hEvents[i], sidRenderContext);
				sids.push_back(sid);
				EvtClose(hEvents[i]);
			}
			catch (...) {
				EvtClose(hEvents[i]);
			}
		}
	}

cleanup:
	for (DWORD i = 0; i < dwReturned; i++) {
		if (NULL != hEvents[i])
			EvtClose(hEvents[i]);
	}

	if (evt){
		EvtClose(evt);
	}
	if (sidRenderContext){
		EvtClose(sidRenderContext);
	}
	

	return sids;
}

void main(void) {
	HMODULE hWevtapi;
	vector<wstring> sids{};
	set<wstring> domainAdmins{};
	set<wstring> results{};
	map<wstring, DWORD> loginCount;
	vector<wstring> json{};

	try{
		if (NULL == (hWevtapi = LoadLibraryW(L"wevtapi.dll")))
		{
			throw runtime_error("Failed to load wevtapi.dll");
		}

		EvtRender = (evtRender_t)GetProcAddress(hWevtapi, "EvtRender");
		EvtCreateRenderContext = (evtCreateRenderContext_t)GetProcAddress(hWevtapi, "EvtCreateRenderContext");
		EvtNext = (evtNext_t)GetProcAddress(hWevtapi, "EvtNext");
		EvtClose = (evtClose_t)GetProcAddress(hWevtapi, "EvtClose");
		EvtQuery = (evtQuery_t)GetProcAddress(hWevtapi, "EvtQuery");
		if (NULL == EvtRender || NULL == EvtCreateRenderContext || NULL == EvtNext || NULL == EvtClose || NULL == EvtQuery) {
			throw runtime_error("Failed to load wevtapi.dll");
		}

		CoInitialize(NULL);

		sids = GetLogonSids();
		domainAdmins = GetDomainAdministrators();

		for (auto sid : sids){
			if (isIn(domainAdmins, sid)){
				results.insert(sid);
				if (loginCount.count(sid)){
					loginCount[sid] += 1;
				}
				else{
					loginCount[sid] = 1;
				}
			}
		}

		for (auto result : results) {
			
			if (json.size() > 0){
				json.push_back(L",");
			}
				
			wstring accountName = ConvertStringSidToAccountName(result);

			json.push_back(L"{\"sid\": \"" + result + L"\", \"name\": \"" + accountName + L"\", \"count\": \"" + to_wstring(loginCount[result]).c_str()  + L"\"}");
		}

		wcout << L"{\"logons\": [";
		for (auto const& s : json) {
			wcout << s.c_str();
		}
		wcout << L"]}";

		CoUninitialize();

	}
	catch (const exception& ex) {
		wcout << L"{\"error\":\"" << ex.what() << L"\"}\r\n";
	}
}