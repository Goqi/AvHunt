package resources

type EDRDetection interface {
	Detect(data SystemData) (EDRType, bool)
	Name() string
	Type() EDRType
}

type EDRType string

var (
	WinDefenderEDR    EDRType = "defender"
	KaskperskyEDR     EDRType = "kaspersky"
	CrowdstrikeEDR    EDRType = "crowdstrike"
	McafeeEDR         EDRType = "mcafee"
	SymantecEDR       EDRType = "symantec"
	CylanceEDR        EDRType = "cylance"
	CarbonBlackEDR    EDRType = "carbon_black"
	SentinelOneEDR    EDRType = "sentinel_one"
	FireEyeEDR        EDRType = "fireeye"
	ElasticAgentEDR   EDRType = "elastic_agent"
	HuorongEDR        EDRType = "huorong"
	SLL360EDR         EDRType = "360"
	TianQingEDR       EDRType = "tianqing"
	JinshanEDR        EDRType = "jinshan"
	SafedogEDR        EDRType = "safedog"
	YunsuoEDR         EDRType = "yunsuo"
	TencentguanjiaEDR EDRType = "guanjia"
	TopsecedrEDR      EDRType = "topsecedr"
)
