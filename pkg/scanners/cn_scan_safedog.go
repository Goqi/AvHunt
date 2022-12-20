package scanners

import "AvHunt/pkg/resources"

type SafedogDetection struct{}

func (w *SafedogDetection) Name() string {
	return "安全狗 Defender"
}

func (w *SafedogDetection) Type() resources.EDRType {
	return resources.SafedogEDR
}

var SafedogProcessHeuristic = []string{
	"SafeDog",
	"SafeDogGuardHelper",
	"SafeDogServerUI",
	"SafeDogTray",
	"Safedog Update Center",
	"SafeDogCloudHelper",
	"SafeDogGuardCenter",
	"safedogupdatecenter",
	"SafeDogSiteIIS",
}

var SafedogServicesHeuristic = []string{
	"SafeDog",
	"SafeDogGuardHelper",
	"SafeDogServerUI",
	"SafeDogTray",
	"Safedog Update Center",
	"SafeDogCloudHelper",
	"SafeDogGuardCenter",
	"safedogupdatecenter",
	"SafeDogSiteIIS",
}

var SafedogDriverHeuristic = []string{
	"SafeDog",
	"SafeDogGuardHelper",
	"SafeDogServerUI",
	"SafeDogTray",
	"Safedog Update Center",
	"SafeDogCloudHelper",
	"SafeDogGuardCenter",
	"safedogupdatecenter",
	"SafeDogSiteIIS",
}

var SafedogRegistryHeuristic = []string{
	"SafeDog",
	"SafeDogGuardHelper",
	"SafeDogServerUI",
	"SafeDogTray",
	"Safedog Update Center",
	"SafeDogCloudHelper",
	"SafeDogGuardCenter",
	"safedogupdatecenter",
	"SafeDogSiteIIS",
}

func (w *SafedogDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(SafedogDriverHeuristic, SafedogProcessHeuristic, SafedogRegistryHeuristic, SafedogServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.SafedogEDR, true
}
