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
	"yunsuo_agent_service",
	"yunsuo_agent_daemon",
}

var YunsuoServicesHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
	"yunsuo_agent_service",
	"yunsuo_agent_daemon",
}

var YunsuoDriverHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
	"yunsuo_agent_service",
	"yunsuo_agent_daemon",
}

var YunsuoRegistryHeuristic = []string{
	"wsssr_defence_daemon",
	"wsssr_defence_service",
	"YSBugReport",
	"YSUpdate",
	"yunsuo_agent_service",
	"yunsuo_agent_daemon",
}

func (w *YunsuoDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(YunsuoDriverHeuristic, YunsuoProcessHeuristic, YunsuoRegistryHeuristic, YunsuoServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.YunsuoEDR, true
}
