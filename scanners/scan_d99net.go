package scanners

import "AvHunt/resources"

type D99netDetection struct{}

func (w *D99netDetection) Name() string {
	return "D盾 Defender"
}

func (w *D99netDetection) Type() resources.EDRType {
	return resources.D99netEDR
}

var D99netProcessHeuristic = []string{
	"D_Safe_Manage",
	"d_manage",
}

var D99netServicesHeuristic = []string{
	"D_Safe_Manage",
	"d_manage",
}

var D99netDriverHeuristic = []string{
	"D_Safe_Manage",
	"d_manage",
}

var D99netRegistryHeuristic = []string{
	"D_Safe_Manage",
	"d_manage",
}

func (w *D99netDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(D99netDriverHeuristic, D99netProcessHeuristic, D99netRegistryHeuristic, D99netServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.D99netEDR, true
}
