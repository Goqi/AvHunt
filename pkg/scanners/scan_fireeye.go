package scanners

import "github.com/Goqi/AvHunt/pkg/resources"

type FireEyeDetection struct{}

func (w *FireEyeDetection) Name() string {
	return "FireEye"
}

func (w *FireEyeDetection) Type() resources.EDRType {
	return resources.FireEyeEDR
}

var FireEyeHeuristic = []string{
	"FireEye",
}

func (w *FireEyeDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(FireEyeHeuristic)
	if !ok {
		return "", false
	}

	return resources.FireEyeEDR, true
}
