package scanners

import "github.com/Goqi/AvHunt/pkg/resources"

type SentinelOneDetection struct{}

func (w *SentinelOneDetection) Name() string {
	return "SentinelOne"
}

func (w *SentinelOneDetection) Type() resources.EDRType {
	return resources.SentinelOneEDR
}

var SentinelOneHeuristic = []string{
	"SentinelOne\\",
	"CbDefense\\",
	"SensorVersion",
}

func (w *SentinelOneDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SentinelOneHeuristic)
	if !ok {
		return "", false
	}

	return resources.SentinelOneEDR, true
}
