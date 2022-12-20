package scanners

import "AvHunt/pkg/resources"

var (
	Scanners = []resources.EDRDetection{
		// 原始版本
		&CarbonBlackDetection{},
		&CrowdstrikeDetection{},
		&CylanceDetection{},
		&FireEyeDetection{},
		&KaskperskyDetection{},
		&McafeeDetection{},
		&SymantecDetection{},
		&SentinelOneDetection{},
		&WinDefenderDetection{},
		&ElasticAgentDetection{},
		// CN
		&HuorongDetection{},
		&SLL360Detection{},
		&TianQingDetection{},
		&JinshanDetection{},
		&SafedogDetection{},
		&YunsuoDetection{},
		&TencentguanjiaDetection{},
		&TopsecedrDetection{},
		&RisingDetection{},
		&JiangminDetection{},
		&AntianDetection{},
		&BaiduDetection{},
		&D99netDetection{},
		&HwsDetection{},
		&MozheDetection{},
		&YaxinDetection{},

		//v1.4.4
		&ESETEDRDetection{},
		&QualysDetection{},
		&TrendMicroDetection{},
		&CybereasonDetection{},
		&BitDefenderDetection{},
		&CheckPointDetection{},
		&CynetDetection{},
		&DeepInstictDetection{},
		&SophosDetection{},
		&FortinetDetection{},
		&MalwareBytesDetection{},
		&LimacharlieDetection{},
	}
)
