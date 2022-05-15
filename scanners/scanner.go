package scanners

import "AvHunt/resources"

var (
	Scanners = []resources.EDRDetection{
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
	}
)
