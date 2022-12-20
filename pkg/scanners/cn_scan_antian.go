package scanners

import "AvHunt/pkg/resources"

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
	"AGB",
	"AHPROCMONSERVER",
}

var AntianServicesHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
	"AGB",
	"AHPROCMONSERVER",
}

var AntianDriverHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
	"AGB",
	"AHPROCMONSERVER",
}

var AntianRegistryHeuristic = []string{
	"AtTray",
	"AtDocSecurity",
	"AtUsbScan",
	"atmain",
	"AtUpdate",
	"AGB",
	"AHPROCMONSERVER",
}

func (w *AntianDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(AntianDriverHeuristic, AntianProcessHeuristic, AntianRegistryHeuristic, AntianServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.AntianEDR, true
}
