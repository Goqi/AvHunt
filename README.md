# AvHunt-杀毒软件识别
[AvHunt](https://github.com/Goqi/AvHunt)是[EDRHunt](https://github.com/FourCoreLabs/EDRHunt)的修改版，添加多个杀毒软件的识别，更容易识别中国的杀毒软件！

## Usage

- Find installed EDRs

```
$ .\AvHunt.exe scan
[EDR]
Detected EDR: Windows Defender
Detected EDR: Kaspersky Security
```

- Scan Everything

```
$ .\AvHunt.exe all
Running in user mode, escalate to admin for more details.
Scanning processes, services, drivers, and registry...
[PROCESSES]

Suspicious Process Name: MsMpEng.exe
Description: MsMpEng.exe
Caption: MsMpEng.exe
Binary:
ProcessID: 6764
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [msmpeng]


Suspicious Process Name: NisSrv.exe
Description: NisSrv.exe
Caption: NisSrv.exe
Binary:
ProcessID: 9840
Parent Process: 1148
Process CmdLine :
File Metadata:
Matched Keyword: [nissrv]
...
```

- Find drivers matching EDR keywords

```
    __________  ____     __  ____  ___   ________
   / ____/ __ \/ __ \   / / / / / / / | / /_  __/
  / __/ / / / / /_/ /  / /_/ / / / /  |/ / / /
 / /___/ /_/ / _, _/  / __  / /_/ / /|  / / /
/_____/_____/_/ |_|  /_/ /_/\____/_/ |_/ /_/

FourCore Labs (https://fourcore.vision) | Version: 1.1

Running in user mode, escalate to admin for more details.
[DRIVERS]
Suspicious Driver Module: WdFilter.sys
Driver FilePath: c:\windows\system32\drivers\wd\wdfilter.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: WdFilter.sys
        InternalFileName: WdFilter
        Company Name: Microsoft Corporation
        FileDescription: Microsoft antimalware file system filter driver
        ProductVersion: 4.18.2109.6
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [antimalware malware]

Suspicious Driver Module: hvsifltr.sys
Driver FilePath: c:\windows\system32\drivers\hvsifltr.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: hvsifltr.sys.mui
        InternalFileName: hvsifltr.sys
        Company Name: Microsoft Corporation
        FileDescription: Microsoft Defender Application Guard Filter Driver
        ProductVersion: 10.0.19041.1
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [defender]

Suspicious Driver Module: WdNisDrv.sys
Driver FilePath: c:\windows\system32\drivers\wd\wdnisdrv.sys
Driver File Metadata:
        ProductName: Microsoft® Windows® Operating System
        OriginalFileName: wdnisdrv.sys
        InternalFileName: wdnisdrv.sys
        Company Name: Microsoft Corporation
        FileDescription: Windows Defender Network Stream Filter
        ProductVersion: 4.18.2109.6
        Comments:
        LegalCopyright: © Microsoft Corporation. All rights reserved.
        LegalTrademarks:
Matched Keyword: [defender]
...
```

- Find services matching EDR keywords

```
$ .\AvHunt.exe -s
```

- Find drivers matching EDR keywords

```
$ .\AvHunt.exe -d
```

- Find registry keys matching EDR keywords

```
$ .\AvHunt.exe -r
```

## AvHunt

AvHunt Detections Currently Available

- 火绒
- 天擎
- 360

## EDRHunt

EDRHunt Detections Currently Available

- Windows Defender
- Kaspersky Security
- Symantec Security
- Crowdstrike Security
- Mcafee Security
- Cylance Security
- Carbon Black
- SentinelOne
- FireEye
- Elastic EDR