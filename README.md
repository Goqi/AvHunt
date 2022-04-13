# AvHunt-杀毒软件识别
[AvHunt](https://github.com/Goqi/AvHunt)是[EDRHunt](https://github.com/FourCoreLabs/EDRHunt)的修改版，添加多个杀毒软件的识别，更容易识别中国的杀毒软件！

## Usage

- Find installed EDRs

```
$ AvHunt.exe scan
[EDR]
Detected EDR: Windows Defender
Detected EDR: 奇虎360 Defender
Detected EDR: 金山毒霸 Defender
Detected EDR: 安全狗 Defender
```

- Scan Everything

```
$ AvHunt.exe all
```

- Find services matching EDR keywords

```
$ AvHunt.exe -s
```

- Find drivers matching EDR keywords

```
$ AvHunt.exe -d
```

- Find registry keys matching EDR keywords

```
$ AvHunt.exe -r
```

## AvHunt

AvHunt Detections Currently Available

- 火绒
- 天擎
- 360
- 金山毒霸
- 安全狗
- 云锁椒图
- 腾讯电脑管家

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