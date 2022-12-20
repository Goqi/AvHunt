/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/20 11:16
*/

package scanners

import "AvHunt/pkg/resources"

type AliYunDunDetection struct{}

func (w *AliYunDunDetection) Name() string {
	return "阿里云盾 Defender"
}

func (w *AliYunDunDetection) Type() resources.EDRType {
	return resources.AliYunDunEDR
}

var AliYunDunProcessHeuristic = []string{
	"AliSecGuard",
	"AliYunDunUpdate",
	"AliYunDun",
	"CmsGoAgent.windows-amd64",
}

var AliYunDunServicesHeuristic = []string{
	"AliSecGuard",
	"AliYunDunUpdate",
	"AliYunDun",
	"CmsGoAgent.windows-amd64",
}

var AliYunDunDriverHeuristic = []string{
	"AliSecGuard",
	"AliYunDunUpdate",
	"AliYunDun",
	"CmsGoAgent.windows-amd64",
}

var AliYunDunRegistryHeuristic = []string{
	"AliSecGuard",
	"AliYunDunUpdate",
	"AliYunDun",
	"CmsGoAgent.windows-amd64",
}

func (w *AliYunDunDetection) Detect(data resources.SystemData) (resources.EDRType, bool) {
	_, ok := data.CountMatchesAll(AliYunDunDriverHeuristic, AliYunDunProcessHeuristic, AliYunDunRegistryHeuristic, AliYunDunServicesHeuristic)
	if !ok {
		return "", false
	}

	return resources.AliYunDunEDR, true
}
