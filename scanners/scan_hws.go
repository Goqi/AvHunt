package scanners

import "AvHunt/resources"

type HwsDetection struct{}

func (w *HwsDetection) Name() string {
	return "护卫神 Defender"
}

func (w *HwsDetection) Type() resources.EDRType {
	return resources.HwsEDR
}

var HwsProcessHeuristic = []string{
	"HwsPanel",
	"hws_ui",
	"hws",
	"hwsd",
}

var HwsServicesHeuristic = []string{
	"HwsPanel",
	"hws_ui",
	"hws",
	"hwsd",
}

var HwsDriverHeuristic = []string{
	"HwsPanel",
	"hws_ui",
	"hws",
	"hwsd",
}

var HwsRegistryHeuristic = []string{
	"HwsPanel",
	"hws_ui",
	"hws",
	"hwsd",
}

func (w *HwsDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(HwsDriverHeuristic, HwsProcessHeuristic, HwsRegistryHeuristic, HwsServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.HwsEDR, true
}
