package scanners

import "AvHunt/resources"

type HuorongDetection struct{}

func (w *HuorongDetection) Name() string {
	return "火绒 Defender"
}

func (w *HuorongDetection) Type() resources.EDRType {
	return resources.HuorongEDR
}

var HuorongProcessHeuristic = []string{
	"hipstray",
	"wsctrl",
	"usysdiag",
	"HipsDaemon",
	"HipsLog",
	"HipsMain",
	"usysdiag",
	"huorong",
}

var HuorongServicesHeuristic = []string{
	"hipstray",
	"wsctrl",
	"usysdiag",
	"HipsDaemon",
	"HipsLog",
	"HipsMain",
	"usysdiag",
	"huorong",
}

var HuorongDriverHeuristic = []string{
	"hipstray",
	"wsctrl",
	"usysdiag",
	"HipsDaemon",
	"HipsLog",
	"HipsMain",
	"usysdiag",
	"huorong",
}

var HuorongRegistryHeuristic = []string{
	"hipstray",
	"wsctrl",
	"usysdiag",
	"HipsDaemon",
	"HipsLog",
	"HipsMain",
	"usysdiag",
	"huorong",
}

func (w *HuorongDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(HuorongDriverHeuristic, HuorongProcessHeuristic, HuorongRegistryHeuristic, HuorongServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.HuorongEDR, true
}
