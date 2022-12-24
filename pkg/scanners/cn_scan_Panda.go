/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/20 11:20
*/

package scanners

import "AvHunt/pkg/resources"

type PandaDetection struct{}

func (w *PandaDetection) Name() string {
	return "熊猫卫士 Defender"
}

func (w *PandaDetection) Type() resources.EDRType {
	return resources.PandaEDR
}

var PandaProcessHeuristic = []string{
	"PAVFIRES.exe",
	"PAVFNSVR.exe",
	"PAVKRE.exe",
	"PAVPROT.exe",
	"PAVPROXY.exe",
	"PAVPRSRV.exe",
	"PAVSRV51.exe",
	"PAVSS.exe",
}

var PandaServicesHeuristic = []string{
	"PAVFIRES.exe",
	"PAVFNSVR.exe",
	"PAVKRE.exe",
	"PAVPROT.exe",
	"PAVPROXY.exe",
	"PAVPRSRV.exe",
	"PAVSRV51.exe",
	"PAVSS.exe",
}

var PandaDriverHeuristic = []string{
	"PAVFIRES.exe",
	"PAVFNSVR.exe",
	"PAVKRE.exe",
	"PAVPROT.exe",
	"PAVPROXY.exe",
	"PAVPRSRV.exe",
	"PAVSRV51.exe",
	"PAVSS.exe",
}

var PandaRegistryHeuristic = []string{
	"PAVFIRES.exe",
	"PAVFNSVR.exe",
	"PAVKRE.exe",
	"PAVPROT.exe",
	"PAVPROXY.exe",
	"PAVPRSRV.exe",
	"PAVSRV51.exe",
	"PAVSS.exe",
}

func (w *PandaDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(PandaDriverHeuristic, PandaProcessHeuristic, PandaRegistryHeuristic, PandaServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.PandaEDR, true
}
