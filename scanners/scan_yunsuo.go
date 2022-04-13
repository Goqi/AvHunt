package scanners

import "AvHunt/resources"

type YunsuoDetection struct{}

func (w *YunsuoDetection) Name() string {
	return "云锁椒图 Defender"
}

func (w *YunsuoDetection) Type() resources.EDRType {
	return resources.YunsuoEDR
}

var YunsuoProcessHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
}

var YunsuoServicesHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
}

var YunsuoDriverHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
}

var YunsuoRegistryHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
}

func (w *YunsuoDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(YunsuoDriverHeuristic, YunsuoProcessHeuristic, YunsuoRegistryHeuristic, YunsuoServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.YunsuoEDR, true
}
