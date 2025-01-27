package scanners

import "AvHunt/pkg/resources"

type KaskperskyDetection struct{}

func (w *KaskperskyDetection) Name() string {
	return "Kaspersky Security"
}

func (w *KaskperskyDetection) Type() resources.EDRType {
	return resources.KaskperskyEDR
}

var KasperskyHeuristic = []string{
	"kaspersky",
	"avpui.exe",
	"avpservice.dll",
	"avzkrnl.dll",
	"cf_anti_malware_facade.dll",
	"cf_facade.dll",
	"cf_mgmt_facade.dll",
	"cf_response_provider.dll",
	"ckahcomm.dll",
	"ckahrule.dll",
	"ckahum.dll",
	"eka_meta.dll",
	"kasperskylab.kis.ui.dll",
	"am_facade.dll",
	"am_meta.dll",
	"attestation_task.dll",
	"avs_eka.dll",
	"kasperskylab.ksde.ui.dll",
	"kasperskylab.ui.core.dll",
	"kasperskylab.ui.core.visuals.dll",
	"ksdeuimain.dll",
	"avpsus.exe",
	"klnagent.exe",
	"klnsacwsrv.exe",
	"klnagent.exe",
	"kl_platf.exe",
	"klnagwds.exe",
	// 自己添加
	"_avp32.exe",
	"_avpcc.exe",
	"_avpm.exe",
}

func (w *KaskperskyDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(KasperskyHeuristic)
	if !ok {
		return "", false
	}

	return resources.KaskperskyEDR, true
}
