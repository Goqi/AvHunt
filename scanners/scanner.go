package scanners

import "github.com/Goqi/AvHunt/resources"

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
	}
)
