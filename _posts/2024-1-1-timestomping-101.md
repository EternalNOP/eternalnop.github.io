---
layout: single
classes: wide
title:  "Timestomping 101"
date:   2024-1-1 12:01:57 +0100
---

# Basics of Timestomping
This post will try and be all encompassing about timestomping such as what it is, how it is used, who it is used by, and various ways to detect it. Time stomping is a anti-forensics red team tactic centered around changing the time attribute of various objects such as files, directories, registries, etc. Various red teams and APTs will use timestomping to try and blend into their environment. Defenders can be given a false sense of security if a malicious file has the same timestamp as other files in the same directory, indicating that the malicious file has always been there. This blog will cover how to change the created, modified, accessed times of a file.

## Different Ways to Perform Timestomping
Below is a list of some ways to perform timestomping
* PowerShell
* SetFileTime

### PowerShell
This is by far the easiest and most straightforward method to changing attributes of a file.
```PowerShell
Get-ChildItem C:\Users\Admin\Desktop\testFile.txt | % {$_.CreationTime = '01/01/2024 03:13:37'}
```

![PowerShell Modifying Create Time](/assets/img/Timestomping-101/testFilePowerShellCreateChange.png)

To change a different attribute of the file swap out the CreationTime value to the other possible values such as LastAccessTime and LastWriteTime.

### SetFileTime
Using the Win32 API function SetFileTime it is possible to change the created, last accessed, or last modified time.
```c
BOOL SetFileTime(
  [in]           HANDLE         hFile,
  [in, optional] const FILETIME *lpCreationTime,
  [in, optional] const FILETIME *lpLastAccessTime,
  [in, optional] const FILETIME *lpLastWriteTime
);
```

Below is a simple program I created to change the timestamp of a targeted file
```c
#include <Windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
	if (argc != 4) {
		printf("Usage: timestomp.exe <file> <method> <time>\n1 = Creation Time\n2 = Last Access Time\n3 = Last Write Time");
		exit(0);
	}

	printf("[+] Attempting to change time of file %s\n", argv[1]);

	//Open handle to target file with required permissions
	HANDLE hFile = NULL;
	hFile = CreateFileA(argv[1], FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	FILETIME createTime, accessTime, lastWriteTime;
	int changedTime, method, retValue = 0;
	
	//Convert program arguments to int types
	method = atoi(argv[2]);
	changedTime = atoi(argv[3]);

	//Change file time based on method choice
	switch (method) {
		case 1:
			printf("[+] Changing create time\n");
			createTime.dwHighDateTime = changedTime;
			retValue = SetFileTime(hFile, &changedTime, NULL, NULL);
			break;
		case 2:
			printf("[+] Changing access time\n");
			accessTime.dwHighDateTime = changedTime;
			retValue = SetFileTime(hFile, NULL, &changedTime, NULL);
			break;
		case 3:
			printf("[+] Changing last write time\n");
			lastWriteTime.dwHighDateTime = changedTime;
			retValue = SetFileTime(hFile, NULL, NULL, &changedTime);
			break;
		default:
			printf("[+] Invalid choice.\n");
			break;
	}


	if (retValue != 0) {
		printf("[+] File time successfully changed\n");
		CloseHandle(hFile);
		exit(0);
	}
	else {
		printf("[+] Changing file time failed\n");
		CloseHandle(hFile);
		exit(1);
	}
}
```

![Timestomping Program Usage](/assets/img/Timestomping-101/timestompingUsage.png)

A test text file is created, the example program will change the create time of the file to April 11, 2024. This program has the capability to change the created, modified, and access time.

![Timestomping Program Usage](/assets/img/Timestomping-101/testFile.png)

As this program was created as a proof of concept, the caveat is precision of the time that the file is changed to.

![Timestomping Program Usage](/assets/img/Timestomping-101/timestompingSuccessfulChange.png)

The last argument of the program is the high-order parts of the [FILETIME structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime). This structure uses time based on 100-nanosecond intervals since January 1, 1601 (UTC).

![Timestomping Program Usage](/assets/img/Timestomping-101/testFilePowerShellCreateChange.png)

# Who Uses Timestomping
Various APTs, commercial red teaming tools, and sophisticated attackers have used timestomping techniques in the past. Cobalt Strike has the [timestomp](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_upload-download-files.htm) command that can change the modified, accessed, and created times of one file to another file. Various APTs and sophisticated attackers have used timestomping in their attacks to make their implants blend into their environment, a good examples is [Stuxnet](https://www.wired.com/images_blogs/threatlevel/2011/02/Symantec-Stuxnet-Update-Feb-2011.pdf) that will change the time of 2 malicious drivers that are uploaded to the system to match the time of other files in the same directory. [MITRE](https://attack.mitre.org/techniques/T1070/006/) has a good list of references of what groups have used timestomping in their attacks.

# Ways to Detect Timestomping

## Win32 Detection
This detection can be very difficult depending on the implementation of the program. A good indicator is whether or not SetFileTime was implemented correctly is to look at the granular time of the modified times. What this means is sometimes attackers will set the date but not necessarily the specific time. The low order bits of the timestamp might be zeroed out indicating that it was not implemented entirely correctly.

## PowerShell Command History
If a file’s time gets changed via PowerShell, looking at the command history of PowerShell for the user context the command was run in will show the command that was run.

The PowerShell command history can be found here
```PowerShell
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Console_history.txt
```