package scanners

import "AvHunt/resources"

type TopsecedrDetection struct{}

func (w *TopsecedrDetection) Name() string {
	return "天融信EDR Defender"
}

func (w *TopsecedrDetection) Type() resources.EDRType {
	return resources.TopsecedrEDR
}

var TopsecedrProcessHeuristic = []string{
	"Topsec",
	"TopsecMain",
	"TopsecTray",
	"TopsecDaemon",
	"TopsecConfig",
	"TopsecLog",
	"TopsecUpdate",
	"TopsecWSCtrl",
}

var TopsecedrServicesHeuristic = []string{
	"Topsec",
	"TopsecMain",
	"TopsecTray",
	"TopsecDaemon",
	"TopsecConfig",
	"TopsecLog",
	"TopsecUpdate",
	"TopsecWSCtrl",
}

var TopsecedrDriverHeuristic = []string{
	"Topsec",
	"TopsecMain",
	"TopsecTray",
	"TopsecDaemon",
	"TopsecConfig",
	"TopsecLog",
	"TopsecUpdate",
	"TopsecWSCtrl",
}

var TopsecedrRegistryHeuristic = []string{
	"Topsec",
	"TopsecMain",
	"TopsecTray",
	"TopsecDaemon",
	"TopsecConfig",
	"TopsecLog",
	"TopsecUpdate",
	"TopsecWSCtrl",
}

func (w *TopsecedrDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TopsecedrDriverHeuristic, TopsecedrProcessHeuristic, TopsecedrRegistryHeuristic, TopsecedrServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.TopsecedrEDR, true
}
