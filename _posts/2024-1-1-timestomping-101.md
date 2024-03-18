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
* GetFileTime/SetFileTime

### PowerShell
This is by far the easiest and most straightforward method to changing attributes of a file.
```PowerShell
Get-ChildItem C:\Users\Admin\Desktop\testFile.txt | % {$_.CreationTime = '01/01/2024 03:13:37'}
```

![PowerShell Modifying Create Time](/assets/img/Timestomping-101/testFilePowerShellCreateChange.png)

To change a different attribute of the file swap out the CreationTime value to the other possible values such as LastAccessTime and LastWriteTime.

### GetFileTime
Retrieves the creation, last access, and last written times from a specified file handle. The only security attribute the handle requires is GENERIC_READ.
```c
BOOL GetFileTime(
  [in]            HANDLE     hFile,
  [out, optional] LPFILETIME lpCreationTime,
  [out, optional] LPFILETIME lpLastAccessTime,
  [out, optional] LPFILETIME lpLastWriteTime
);
```

This [win32 function](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletime) is used in order to retrieve time values that Windows can understand. The FILETIME structure that Windows uses is different than what most of us are familiar with. It is a “64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)”. This is quite different than the standard epoch time that Unix uses of number of seconds from January 1, 1970. The FILETIME structure also is  divided into 2 DWORD elements of dwLowDateTime and dwHighDateTime. In order to accurately change both values the documentation recommends copying the values into a ULARGE_INTEGER and then performing some arithmetic on the QuadPart member.
```c
typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;
```

Doing 64-bit arithmetic to manually set both elements in a FILETIME structure is outside the scope of this post and not needed when GetFileTime and SetFileTime both understand and use the FILETIME structure.

### SetFileTime
Using the Win32 API function [SetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime) it is possible to change the created, last accessed, or last modified time based on a valid handle that has the GENERIC_WRITE attribute.
```c
BOOL SetFileTime(
  [in]           HANDLE         hFile,
  [in, optional] const FILETIME *lpCreationTime,
  [in, optional] const FILETIME *lpLastAccessTime,
  [in, optional] const FILETIME *lpLastWriteTime
);
```

A snippet of the use of GetFileTime and SetFileTime is shown below. The full project can be found on my [GitHub](https://github.com/EternalNOP/Timestomping).
```c
printf("[+] Retreiving all file times\n");
if(GetFileTime(inFile, &creationTime, &lastAccessTime, &lastWriteTime) == 0) {
	printf("Error retreiving file information: %d\n", GetLastError());
	return 1;
}

printf("[+] Successfully retreived file times\n");


printf("[+] Writing all times to output file\n");
if (SetFileTime(outFile, &creationTime, &lastAccessTime, &lastWriteTime) == 0) {
	printf("[+] Error writing to output file: %d\n", GetLastError());
	return 2;
}
```

# Who Uses Timestomping
Various APTs, commercial red teaming tools, and sophisticated attackers have used timestomping techniques in the past. Cobalt Strike has the [timestomp](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_upload-download-files.htm) command that can change the modified, accessed, and created times of one file to another file. Various APTs and sophisticated attackers have used timestomping in their attacks to make their implants blend into their environment, a good examples is [Stuxnet](https://www.wired.com/images_blogs/threatlevel/2011/02/Symantec-Stuxnet-Update-Feb-2011.pdf) that will change the time of 2 malicious drivers that are uploaded to the system to match the time of other files in the same directory. [MITRE](https://attack.mitre.org/techniques/T1070/006/) has a good list of references of what groups have used timestomping in their attacks.

# Ways to Detect Timestomping

## Win32 Detection
This detection can be very difficult depending on the implementation of the program. A good indicator can be two files within the same directory that have the exact same creation, written, and access times. The biggest limitation that this program currently has is it doesn’t create a random offset based on an input file to write it to the destination file. I leave that as an assignment to the reader.

This is dependent on the environment setup but [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) has an [event ID](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002) if a process changed the creation time of another file.

A test text file is created, the example program has multiple options to change either all times from a specified input file or specifically selecting just one attribute. In order to see if Sysmon can correctly detect timestomping, the text file times will be changed to the Microsoft Edge shortcut file located in the same directory.

![Microsoft Edge LNK Time](/assets/img/Timestomping-101/EdgeLNK.png)

Below is the command-line arguments used for the Timestomping.exe application

```
Timestomping.exe
Usage: timestomp.exe <method> <input file> <output file>
method  1 = All available timestamps
        2 = CreationTime
        3 = AccessTime
        4 = LastWriteTime


Timestomping.exe 1 "Microsoft Edge.lnk" test.txt
```

![Modified TXT Time](/assets/img/Timestomping-101/ModifiedTXT.png)

The affected test.txt file had all of their times changed to by the same as the Microsoft Edge LNK file. Using a slightly modified version of a [recommended baseline](https://github.com/SwiftOnSecurity/sysmon-config) Sysmon configuration file, an alert ID of 2 was generated by Sysmon.

In order to detect timestomping for text files, the below line was added to the configuration file under the FileCreateTime rule section.
```
<TargetFilename name="T1099" condition="end with">.txt</TargetFilename>
```

The downside for this detection is that without specific system policy changes, Sysmon cannot log command-line arguments. This is outside the scope of this post but Microsoft does provide [documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) on how to set that up.

To circumvent being caught by this logging activity, an attacker may only write the last accessed and last written time. This somewhat defeats the purpose as those times are more subject to change than the creation time.

## PowerShell Command History
If a file’s time gets changed via PowerShell, looking at the command history of PowerShell for the user context the command was run in will show the command that was run.

The PowerShell command history can be found here
```PowerShell
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Console_history.txt
```