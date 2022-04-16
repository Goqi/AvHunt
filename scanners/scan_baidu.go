package scanners

import "AvHunt/resources"

type BaiduDetection struct{}

func (w *BaiduDetection) Name() string {
	return "百度杀毒 Defender"
}

func (w *BaiduDetection) Type() resources.EDRType {
	return resources.BaiduEDR
}

var BaiduProcessHeuristic = []string{
	"BaiduSdSvc",
	"BaiduSdTray",
	"BaiduSd",
	"bddownloader",
	"baiduansvx",
}

var BaiduServicesHeuristic = []string{
	"BaiduSdSvc",
	"BaiduSdTray",
	"BaiduSd",
	"bddownloader",
	"baiduansvx",
}

var BaiduDriverHeuristic = []string{
	"BaiduSdSvc",
	"BaiduSdTray",
	"BaiduSd",
	"bddownloader",
	"baiduansvx",
}

var BaiduRegistryHeuristic = []string{
	"BaiduSdSvc",
	"BaiduSdTray",
	"BaiduSd",
	"bddownloader",
	"baiduansvx",
}

func (w *BaiduDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(BaiduDriverHeuristic, BaiduProcessHeuristic, BaiduRegistryHeuristic, BaiduServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.BaiduEDR, true
}
