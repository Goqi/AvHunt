package scanners

import "AvHunt/resources"

type AntianDetection struct{}

func (w *AntianDetection) Name() string {
	return "安天杀毒 Defender"
}

func (w *AntianDetection) Type() resources.EDRType {
	return resources.AntianEDR
}

var AntianProcessHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
}

var AntianServicesHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
}

var AntianDriverHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
}

var AntianRegistryHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
}

func (w *AntianDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(AntianDriverHeuristic, AntianProcessHeuristic, AntianRegistryHeuristic, AntianServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.AntianEDR, true
}
