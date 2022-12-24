package scanners

import "AvHunt/pkg/resources"

type TianQingDetection struct{}

func (w *TianQingDetection) Name() string {
	return "奇安信天擎 Defender"
}

func (w *TianQingDetection) Type() resources.EDRType {
	return resources.TianQingEDR
}

var TianQingProcessHeuristic = []string{
	"Endpoint Security Management System",
	"攻击发现与风险控制系统",
	"FcTray",
	"QAXEntClient",
	"QAXEntClient",
	"QAXTray",
	"QaxEngManager",
	"QAX",
}

var TianQingServicesHeuristic = []string{
	"Endpoint Security Management System",
	"攻击发现与风险控制系统",
	"FcTray",
	"QAXEntClient",
	"QAXEntClient",
	"QAXTray",
	"QaxEngManager",
	"QAX",
}

var TianQingDriverHeuristic = []string{
	"Endpoint Security Management System",
	"攻击发现与风险控制系统",
	"FcTray",
	"QAXEntClient",
	"QAXEntClient",
	"QAXTray",
	"QaxEngManager",
	"QAX",
}

var TianQingRegistryHeuristic = []string{
	"Endpoint Security Management System",
	"攻击发现与风险控制系统",
	"FcTray",
	"QAXEntClient",
	"QAXEntClient",
	"QAXTray",
	"QaxEngManager",
	"QAX",
}

func (w *TianQingDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TianQingDriverHeuristic, TianQingProcessHeuristic, TianQingRegistryHeuristic, TianQingServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.TianQingEDR, true
}
