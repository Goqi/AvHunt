package scanners

import "AvHunt/pkg/resources"

type MozheDetection struct{}

func (w *MozheDetection) Name() string {
	return "墨者安全 Defender"
}

func (w *MozheDetection) Type() resources.EDRType {
	return resources.MozheEDR
}

var MozheProcessHeuristic = []string{
	"ananwidget",
}

var MozheServicesHeuristic = []string{
	"ananwidget",
}

var MozheDriverHeuristic = []string{
	"ananwidget",
}

var MozheRegistryHeuristic = []string{
	"ananwidget",
}

func (w *MozheDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(MozheDriverHeuristic, MozheProcessHeuristic, MozheRegistryHeuristic, MozheServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.MozheEDR, true
}
