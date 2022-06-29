package scanners

import "AvHunt/resources"

type YaxinDetection struct{}

func (w *YaxinDetection) Name() string {
	return "亚信安全 Defender"
}

func (w *YaxinDetection) Type() resources.EDRType {
	return resources.YaxinEDR
}

var YaxinProcessHeuristic = []string{
	"Deep Security Notified",
	"Deep Security Monitor",
	"Deep Security Agent",
	"Notifier.exe",
	"ds_monitor.exe",
	"dsa.exe",
}

var YaxinServicesHeuristic = []string{
	"Deep Security Notified",
	"Deep Security Monitor",
	"Deep Security Agent",
	"Notifier.exe",
	"ds_monitor.exe",
	"dsa.exe",
}

var YaxinDriverHeuristic = []string{
	"Deep Security Notified",
	"Deep Security Monitor",
	"Deep Security Agent",
	"Notifier.exe",
	"ds_monitor.exe",
	"dsa.exe",
}

var YaxinRegistryHeuristic = []string{
	"Deep Security Notified",
	"Deep Security Monitor",
	"Deep Security Agent",
	"Notifier.exe",
	"ds_monitor.exe",
	"dsa.exe",
}

func (w *YaxinDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(YaxinDriverHeuristic, YaxinProcessHeuristic, YaxinRegistryHeuristic, YaxinServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.YaxinEDR, true
}
