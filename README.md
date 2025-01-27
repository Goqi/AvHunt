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
- 天融信EDR
- 瑞星杀毒
- 江民杀毒
- 安天杀毒
- 百度杀毒
- D盾
- 护卫神
- 墨者安全
- 亚信安全
- 阿里云盾
- 熊猫卫士

以下待更新

- 深信服EDR
- 绿盟EDR

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
- Qualys EDR
- Trend Micro EDR
- ESET EDR
- Cybereason EDR
- BitDefender EDR
- Checkpoint EDR
- Cynet EDR
- DeepInstinct EDR
- Sophos EDR
- Fortinet EDR
- MalwareBytes EDR
- LimaCharlie Agent

## Todo

- https://github.com/wwl012345/AVCheck