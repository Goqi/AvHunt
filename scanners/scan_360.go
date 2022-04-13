package scanners

import "github.com/Goqi/AvHunt/resources"

type SLL360Detection struct{}

func (w *SLL360Detection) Name() string {
	return "360 Defender"
}

func (w *SLL360Detection) Type() resources.EDRType {
	return resources.SLL360EDR
}

var SLL360ProcessHeuristic = []string{
	"360sd.exe",
	"360tray.exe",
	"ZhuDongFangYu.exe",
	"360rp.exe",
	"360safe.exe",
	"360safebox.exe",
	"QHActiveDefense.exe",
	"360skylarsvc.exe",
	"LiveUpdate360.exe",
}

var SLL360ServicesHeuristic = []string{
	"360sd",
	"360tray",
	"ZhuDongFangYu",
	"360rp",
	"360safe",
	"360safebox",
	"QHActiveDefense",
	"360skylarsvc",
	"LiveUpdate360",
}

var SLL360DriverHeuristic = []string{
	"360sd",
	"360tray",
	"ZhuDongFangYu",
	"360rp",
	"360safe",
	"360safebox",
	"QHActiveDefense",
	"360skylarsvc",
	"LiveUpdate360",
}

var SLL360RegistryHeuristic = []string{
	"360sd",
	"360tray",
	"ZhuDongFangYu",
	"360rp",
	"360safe",
	"360safebox",
	"QHActiveDefense",
	"360skylarsvc",
	"LiveUpdate360",
}

func (w *SLL360Detection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SLL360DriverHeuristic, SLL360ProcessHeuristic, SLL360RegistryHeuristic, SLL360ServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.SLL360EDR, true
}
