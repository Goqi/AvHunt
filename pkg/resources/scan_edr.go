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
	RisingEDR         EDRType = "rising"
	JiangminEDR       EDRType = "jiangmin"
	AntianEDR         EDRType = "antian"
	BaiduEDR          EDRType = "baidu"
	D99netEDR         EDRType = "d99net"
	HwsEDR            EDRType = "hws"
	MozheEDR          EDRType = "mozhe"
	YaxinEDR          EDRType = "Yaxin"
	AliYunDunEDR      EDRType = "aliyundun"
	PandaEDR          EDRType = "Panda"

	//v1.4.4
	QualysEDR       EDRType = "qualys"
	TrendMicroEDR   EDRType = "trend_micro"
	ESETEDR         EDRType = "eset"
	CybereasonEDR   EDRType = "cybereason"
	BitDefenderEDR  EDRType = "bitdefender"
	CheckPointEDR   EDRType = "checkpoint"
	CynetEDR        EDRType = "cynet"
	DeepInstinctEDR EDRType = "deepinstinct"
	SophosEDR       EDRType = "sophos"
	FortinetEDR     EDRType = "fortinet"
	MalwareBytesEDR EDRType = "malwarebytes"
	LimacharlieEDR  EDRType = "limacharlie"
)
