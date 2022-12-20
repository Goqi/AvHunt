package scanners

import "AvHunt/pkg/resources"

type JiangminDetection struct{}

func (w *JiangminDetection) Name() string {
	return "江民杀毒 Defender"
}

func (w *JiangminDetection) Type() resources.EDRType {
	return resources.JiangminEDR
}

var JiangminProcessHeuristic = []string{
	"KvPad",
	"KVMonXP",
	"KVHistory",
	"KVInfoBarUI",
	"KVPreScan",
}

var JiangminServicesHeuristic = []string{
	"KvPad",
	"KVMonXP",
	"KVHistory",
	"KVInfoBarUI",
	"KVPreScan",
}

var JiangminDriverHeuristic = []string{
	"KvPad",
	"KVMonXP",
	"KVHistory",
	"KVInfoBarUI",
	"KVPreScan",
}

var JiangminRegistryHeuristic = []string{
	"KvPad",
	"KVMonXP",
	"KVHistory",
	"KVInfoBarUI",
	"KVPreScan",
}

func (w *JiangminDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(JiangminDriverHeuristic, JiangminProcessHeuristic, JiangminRegistryHeuristic, JiangminServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.JiangminEDR, true
}
