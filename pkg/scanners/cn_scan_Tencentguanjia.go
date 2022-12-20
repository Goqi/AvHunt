package scanners

import "AvHunt/pkg/resources"

type TencentguanjiaDetection struct{}

func (w *TencentguanjiaDetection) Name() string {
	return "腾讯电脑管家 Defender"
}

func (w *TencentguanjiaDetection) Type() resources.EDRType {
	return resources.TencentguanjiaEDR
}

var TencentguanjiaProcessHeuristic = []string{
	"QMDL",
	"QMDLP",
	"QMExtraPackageSetup",
	"QMInterfaceExe",
	"QMLaunch",
	"QMLoginAssistant",
	"QMLspPing",
	"QMNetProxyClient",
	"QMNetProxyHost",
	"QMPersonalCenter",
	"QMProviderUpdate",
	"QMSignScan",
	"QMSmbAssistor",
	"QMStateCheck",
	"QMSuperScan",
	"QMUpload",
	"QMUsbGuard",
	"QQPCTray",
}

var TencentguanjiaServicesHeuristic = []string{
	"QMDL",
	"QMDLP",
	"QMExtraPackageSetup",
	"QMInterfaceExe",
	"QMLaunch",
	"QMLoginAssistant",
	"QMLspPing",
	"QMNetProxyClient",
	"QMNetProxyHost",
	"QMPersonalCenter",
	"QMProviderUpdate",
	"QMSignScan",
	"QMSmbAssistor",
	"QMStateCheck",
	"QMSuperScan",
	"QMUpload",
	"QMUsbGuard",
	"QQPCTray",
}

var TencentguanjiaDriverHeuristic = []string{
	"QMDL",
	"QMDLP",
	"QMExtraPackageSetup",
	"QMInterfaceExe",
	"QMLaunch",
	"QMLoginAssistant",
	"QMLspPing",
	"QMNetProxyClient",
	"QMNetProxyHost",
	"QMPersonalCenter",
	"QMProviderUpdate",
	"QMSignScan",
	"QMSmbAssistor",
	"QMStateCheck",
	"QMSuperScan",
	"QMUpload",
	"QMUsbGuard",
	"QQPCTray",
}

var TencentguanjiaRegistryHeuristic = []string{
	"QMDL",
	"QMDLP",
	"QMExtraPackageSetup",
	"QMInterfaceExe",
	"QMLaunch",
	"QMLoginAssistant",
	"QMLspPing",
	"QMNetProxyClient",
	"QMNetProxyHost",
	"QMPersonalCenter",
	"QMProviderUpdate",
	"QMSignScan",
	"QMSmbAssistor",
	"QMStateCheck",
	"QMSuperScan",
	"QMUpload",
	"QMUsbGuard",
	"QQPCTray",
}

func (w *TencentguanjiaDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(TencentguanjiaDriverHeuristic, TencentguanjiaProcessHeuristic, TencentguanjiaRegistryHeuristic, TencentguanjiaServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.TencentguanjiaEDR, true
}
