package scanners

import "AvHunt/pkg/resources"

type TrendMicroDetection struct{}

func (w *TrendMicroDetection) Name() string {
	return "Trend Micro Deep Security"
}

func (w *TrendMicroDetection) Type() resources.EDRType {
	return resources.TrendMicroEDR
}

var TrendMicroHeuristic = []string{
	"Trend Micro",
	"pccntmon.exe",
	"AosUImanager.exe",
	"NTRTScan.exe",
	"tmaseng.dll",
	"TMAS_OL.exe",
	"TMAS_OLA.dll",
	"TMAS_OLImp.exe",
	"TMAS_OLShare.dll",
	"EMapiWpr.dll",
	"TMAS_OLSentry.exe",
	"ufnavi.exe",
	"Clnrbin.exe",
	"vizorhtmldialog.exe",
	"pwmConsole.exe",
	"PwmSvc.exe",
	"coreServiceShell.exe",
	"ds_agent.exe",
	"ufnavi.exe",
	"SfCtlCom.exe",
	//自己添加
	"PCCPFW.exe",
	"PCCTLCOM.exe",
	"TMLISTEN.exe",
	"TMNTSRV.exe",
	"TMPROXY.exe",
}

func (w *TrendMicroDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TrendMicroHeuristic)
	if !ok {
		return "", false
	}

	return resources.QualysEDR, true
}
