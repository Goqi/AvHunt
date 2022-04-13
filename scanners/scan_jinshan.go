package scanners

import "AvHunt/resources"

type JinshanDetection struct{}

func (w *JinshanDetection) Name() string {
	return "金山毒霸 Defender"
}

func (w *JinshanDetection) Type() resources.EDRType {
	return resources.JinshanEDR
}

var JinshanProcessHeuristic = []string{
	"kxescore",
	"kupdata",
	"kxetray",
	"kwsprotect64",
}

var JinshanServicesHeuristic = []string{
	"kxescore",
	"kupdata",
	"kxetray",
	"kwsprotect64",
}

var JinshanDriverHeuristic = []string{
	"kxescore",
	"kupdata",
	"kxetray",
	"kwsprotect64",
}

var JinshanRegistryHeuristic = []string{
	"kxescore",
	"kupdata",
	"kxetray",
	"kwsprotect64",
}

func (w *JinshanDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(JinshanDriverHeuristic, JinshanProcessHeuristic, JinshanRegistryHeuristic, JinshanServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.JinshanEDR, true
}
