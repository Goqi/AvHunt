package scanners

import "AvHunt/pkg/resources"

type McafeeDetection struct{}

func (w *McafeeDetection) Name() string {
	return "McAfee MVISION Endpoint Detection and Response"
}

func (w *McafeeDetection) Type() resources.EDRType {
	return resources.McafeeEDR
}

var McafeeHeuristic = []string{
	"Mcafee\\",
	"mcupdate.exe",
	"McAfeeAgent\\",
	"APPolicyName",
	"EPPolicyName",
	"OASPolicyName",
	"ESConfigTool.exe",
	"FWInstCheck.exe",
	"FwWindowsFirewallHandler.exe",
	"mfeesp.exe",
	"mfefw.exe",
	"mfeProvisionModeUtility.exe",
	"mfetp.exe",
	"WscAVExe.exe",
	"mcshield.exe",
	"McChHost.exe",
	"mfewc.exe",
	"mfewch.exe",
	"mfewcui.exe",
	"mfecanary.exe",
	"mfefire.exe",
	"mfehidin.exe",
	"mfemms.exe",
	"mfevtps.exe",
	"MarSetup.exe",
	"masvc.exe",
	"macmnsvc.exe",
	"MfeServiceMgr.exe ",
	"McAPExe.exe",
	"McPvTray.exe",
	"mcuicnt.exe",
	"mcuihost.exe",
	"Mcshield.exe",
	"McpService.exe",
	"Tbmon.exe",
	"Frameworkservice.exe",
	"epefprtrainer.exe",
	"mfeffcoreservice.exe",
	"MfeEpeSvc.exe",
	//自己添加
	"firesvc.exe",
	"firetray.exe",
	"hipsvc.exe",
	"mfevtps.exe",
	"mcafeefire.exe",
	"scan32.exe",
	"shstat.exe",
	"vstskmgr.exe",
	"engineserver.exe",
	"mfeann.exe",
	"mcscript.exe",
	"updaterui.exe",
	"udaterui.exe",
	"naprdmgr.exe",
	"cleanup.exe",
	"cmdagent.exe",
	"frminst.exe",
	"mcscript_inuse.exe",
	"mctray.exe",
}

func (w *McafeeDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(McafeeHeuristic)
	if !ok {
		return "", false
	}

	return resources.McafeeEDR, true
}
