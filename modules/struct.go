package modules

type IdsAlert struct {
	Time         uint64  `json:time`
	Src_ip       string  `json:srcIp`
	Src_ip_info  SIpInfo `json:src_ip_info`
	Src_port     uint32  `json:srcPort`
	Dest_ip      string  `json:destIp`
	Dest_ip_info DIpInfo `json:dst_ip_info`
	Dest_port    uint32  `json:destPort`
	Proto        uint32  `json:protocol`
	Byzoro_type  string  `json:byzoroType`
	Attack_type  string  `json:attackType`
	Details      string  `json:details`
	Severity     uint32  `json:severity`
	Engine       string  `json:engine`
}

type WafAlert struct {
	Client    string       `json:"client"`
	Rev       string       `json:"rev"`
	Msg       string       `json:"msg"`
	Attack    string       `json:"attack"`
	Severity  int32        `json:"severity"`
	Maturity  int32        `json:"maturity"`
	Accuracy  int32        `json:"accuracy"`
	Hostname  string       `json:"hostName"`
	Uri       string       `json:"uri"`
	Unique_id string       `json:"unique_id"`
	Ref       string       `json:"ref"`
	Tags      []string     `json:"tags"`
	Rule      WafAlertRule `json:"Rule"`
	Version   string       `json:"version"`
	Xdr       []BackendObj `json:"xdr"`
}

type VdsAlert struct {
	Log_time         int          `json:"logTime"`
	Threatname       string       `json:"threatName"`
	Local_threatname string       `json:"localThreatName"`
	Local_vtype      string       `json:"localVType"`
	Local_platfrom   string       `json:"localPlatfrom"`
	Local_vname      string       `json:"localVName"`
	Local_extent     string       `json:"localExtent"`
	Local_enginetype string       `json:"localEngineType"`
	Local_logtype    string       `json:"localLogType"`
	Local_engineip   string       `json:"localEngineIp"`
	Xdr              []BackendObj `json:"xdr"`
}

type WafAlertObj struct {
	BackendObj
	Alert WafAlert `json:"Alert"`
}
type VdsAlertObj struct {
	BackendObj
	Alert VdsAlert `json:"Alert"`
}
type BackendObj struct {
	Vendor      string       `json:Verdor`
	Id          uint64       `json:id`
	Ipv4        bool         `json:Ipv4`
	Class       uint8        `json:Class`
	Type        uint32       `json:Type`
	Time        uint64       `json:Time`
	Offline_Tag string       `json:Offline_Tag`
	Task_Id     string       `json:Task_Id`
	Conn        Conn_backend `json:Conn`
	ConnEx      struct {
		Over bool `json:Over`
		Dir  bool `json:Dir`
	} `json:ConnEx`
	ConnSt struct {
		FlowUp     uint64 `json:FlowUp`
		FlowDown   uint64 `json:FlowDown`
		PktUp      uint64 `json:PktUp`
		PktDown    uint64 `json:PktDown`
		IpFragUp   uint64 `json:IpFragUp`
		IpFragDown uint64 `json:IpFragDown`
	} `json:ConnEt`
	ConnTime struct {
		Start uint64 `json:Start`
		End   uint64 `json:End`
	} `json:ConnTime`
	ServSt struct {
		FlowUp          uint64 `json:FlowUp`
		FlowDown        uint64 `json:FlowDown`
		PktUp           uint64 `json:PktUp`
		PktDown         uint64 `json:PktDown`
		IpFragUp        uint64 `json:IpFragUp`
		IpFragDown      uint64 `json:IpFragDown`
		TcpDisorderUp   uint64 `json:TcpDisorderUp`
		TcpDisorderDown uint64 `json:TcpDisorderDown`
		TcpRetranUp     uint64 `json:TcpRetranUp`
		TcpRetranDown   uint64 `json:TcpRetranDown`
	} `json:ServSt`
	Tcp struct {
		DisorderUp        uint64 `json:DisorderUp`
		DisorderDown      uint64 `json:DisorderDown`
		RetranUp          uint64 `json:RetranUp`
		RetranDown        uint64 `json:RetranDown`
		SynAckDelay       uint16 `json:SynAckDelay`
		AckDelay          uint16 `json:AckDelay`
		ReportFlag        uint8  `json:ReportFlag`
		CloseReason       uint8  `json:CloseReason`
		FirstRequestDelay uint32 `json:FirstRequestDelay`
		FirstResponseDely uint32 `json:FirstResponseDely`
		Window            uint32 `json:Window`
		Mss               uint16 `json:Mss`
		SynCount          uint64 `json:SynCount`
		SynAckCount       uint64 `json:SynAckCount`
		AckCount          uint8  `json:AckCount`
		SessionOK         bool   `json:SessionOK`
		Handshake12       bool   `json:Handshake12`
		Handshake23       bool   `json:Handshake23`
		Open              int32  `json:Open`
		Close             int32  `json:Close`
	} `json:Tcp`
	Http struct {
		Host              string `json:Host`
		HostIpInfo        IpInfo `json:IpInfo`
		Url               string `json:Url`
		XonlineHost       string `json:XonlineHost`
		UserAgent         string `json:UserAgent`
		ContentType       string `json:ContentType`
		Refer             string `json:Refer`
		Cookie            string `json:Cookie`
		Location          string `json:Location`
		request           []byte
		Request           string `json:Request`
		RequestLocation   LocationHdfs
		response          []byte
		Response          string `json:Response`
		ResponseLocation  LocationHdfs
		RequestTime       uint64 `json:RequestTime`
		FirstResponseTime uint64 `json:FirstResponseTime`
		LastContentTime   uint64 `json:LastContentTime`
		ServTime          uint64 `json:ServTime`
		ContentLen        uint32 `json:ContentLen`
		StateCode         uint16 `json:StateCode`
		Method            uint8  `json:Method`
		Version           uint8  `json:Version`
		HeadFlag          bool   `json:HeadFlag`
		ServFlag          uint8  `json:ServFlag`
		RequestFlag       bool   `json:RequestFlag`
		Browser           uint8  `json:Browser`
		Portal            uint8  `json:Portal`
	} `json:Http`
	Sip struct {
		CallingNo    string `json:CallingNo`
		CalledNo     string `json:CalledNo`
		SessionId    string `json:SessionId`
		CallDir      uint8  `json:CallDir`
		CallType     uint8  `json:CallType`
		HangupReason uint8  `json:HangupReason`
		SignalType   uint8  `json:SignalType`
		StreamCount  uint16 `json:StreamCount`
		Malloc       bool   `json:Malloc`
		Bye          bool   `json:Bye`
		Invite       bool   `json:Invite`
	} `json:Sip`
	Rtsp struct {
		Url              string `json:Url`
		UserAgent        string `json:UserAgent`
		ServerIp         string `json:ServerIp`
		ClientBeginPort  uint16 `json:ClientBeginPort`
		ClientEndPort    uint16 `json:ClientEndPort`
		ServerBeginPort  uint16 `json:ServerBeginPort`
		ServerEndPort    uint16 `json:ServerEndPort`
		VideoStreamCount uint16 `json:VideoStreamCount`
		AudeoStreamCount uint16 `json:AudeoStreamCount`
		ResDelay         uint32 `json:ResDelay`
	} `json:Rtsp`
	Ftp struct {
		State      uint16 `json:"State,omitempty"`
		UserCount  uint64 `json:"UserCount,omitempty"`
		CurrentDir string `json:"CurrentDir,omitempty"`
		TransMode  uint8  `json:"TransMode,omitempty"`
		TransType  uint8  `json:"TransType,omitempty"`
		FileCount  uint64 `json:"FileCount,omitempty"`
		FileSize   uint32 `json:"FileSize,omitempty"`
		RspTm      uint64 `json:"RspTm,omitempty"`
		TransTm    uint64 `json:"TransTm,omitempty"`
	} `json:"Ftp,omitempty"`
	Mail struct {
		MsgType     uint16 `json:"MsgType,omitempty"`
		RspState    uint16 `json:"RspState,omitempty"`
		UserName    string `json:"UserName,omitempty"`
		RecverInfo  string `json:"RecverInfo,omitempty"`
		Len         uint32 `json:"Len,omitempty"`
		DomainInfo  string `json:"DomainInfo,omitempty"`
		RecvAccount string `json:"RecvAccount,omitempty"`
		Hdr         string `json:"Hdr,omitempty"`
		AcsType     uint8  `json:"AcsType,omitempty"`
	} `json:"Mail,omitempty"`
	Dns struct {
		Domain    string   `json:"Domain,omitempty"`
		IpCount   uint8    `json:"IpCount,omitempty"`
		IpVersion uint8    `json:"IpVersion,omitempty"`
		Ip        string   `json:"Ip,omitempty"`
		IpInfo    IpInfo   `json:"IpInfo,omitempty"`
		Ips       []string `json:"Ips,omitempty"`
		IpInfos   []IpInfo `json:"IpInfos,omitempty"`
		//Ipv4             string   `json:Ipv4`
		//Ipv6             string   `json:Ipv6`
		RspCode          uint8  `json:"RspCode,omitempty"`
		ReqCount         uint8  `json:"ReqCount,omitempty"`
		RspRecordCount   uint8  `json:"RspRecordCount,omitempty"`
		AuthCnttCount    uint8  `json:"AuthCnttCount,omitempty"`
		ExtraRecordCount uint8  `json:"ExtraRecordCount,omitempty"`
		RspDelay         uint32 `json:"RspDelay,omitempty"`
		PktValid         bool   `json:"PktValid"`
	} `json:"Dns"`
	Vpn struct {
		Type uint64 `json:"Type,omitempty"`
	} `json:"Vpn,omitempty"`
	Proxy struct {
		Type uint64 `json:"Type,omitempty"`
	} `json:"Proxy,omitempty"`
	QQ struct {
		Number string `json:"Number,omitempty"`
	} `json:"QQ,omitempty"`
	App struct {
		ProtoInfo    uint64 `json:"ProtoInfo,omitempty"`
		Status       uint64 `json:"Status,omitempty"`
		ClassId      uint64 `json:"ClassId,omitempty"`
		Proto        uint64 `json:"Proto,omitempty"`
		file         []byte
		File         string       `json:"File,omitempty"`
		FileLocation LocationHdfs `json:"FileLocation,omitempty"`
	} `json:"App,omitempty"`
	Ssl struct {
		FailReason uint32    `json:"FailReason,omitempty"`
		Server     CertsLink `json:"Server"`
		Client     CertsLink `json:"Client"`
	}
}

type Conn_backend struct {
	Proto   uint8  `json:Proto`
	Sport   uint16 `json:Sport`
	Dport   uint16 `json:Dport`
	Sip     string `json:Sip`
	SipInfo IpInfo `json:SipInfo`
	Dip     string `json:Dip`
	DipInfo IpInfo `json:DipInfo`
}

type CertsLink struct {
	Verfy           bool       `json:"Verfy"`
	VerfyFailedDesc string     `json:"VerfyFailedDesc,omitempty"`
	VerfyFailedIdx  uint32     `json:"VerfyFailedIdx,omitempty"`
	Cert            CertInfo   `json:"Cert,omitempty"`
	Certs           []CertInfo `json:"Certs,omitempty"`
}

type CertInfo struct {
	Version              uint32
	SerialNumber         string
	NotBefore            uint64
	NotAfter             uint64
	KeyUsage             uint32
	CountryName          string
	OrganizationName     string
	OrganizationUnitName string
	CommonName           string
	FileLocation         mysqlLocation
	Data                 []byte `json:"Cert,omitempty"`
}

type LocationHdfs struct {
	Signature string
	Size      int
	Offset    int64
	File      string
}

type WafAlertRule struct {
	Ver  string `json:"ruleVersion"`
	Data string `json:"ruleData"`
	File string `json:"ruleFile"`
	Line uint64 `json:"ruleLine"`
	Id   uint64 `json:"ruleId"`
}

type mysqlLocation struct {
	DbName    string
	TableName string
	Signature string
}

type IpInfo struct {
	Country         string `json:"Country,omitempty"`
	Province        string `json:"Province,omitempty"`
	City            string `json:"City,omitempty"`
	Organization    string `json:"Organization,omitempty"`
	Network         string `json:"Network,omitempty"`
	Lng             string `json:"Lng,omitempty"`
	Lat             string `json:"Lat,omitempty"`
	TimeZone        string `json:"TimeZone,omitempty"`
	UTC             string `json:"UTC,omitempty"`
	RegionalismCode string `json:"RegionalismCode,omitempty"`
	PhoneCode       string `json:"PhoneCode,omitempty"`
	CountryCode     string `json:"CountryCode,omitempty"`
	ContinentCode   string `json:"ContinentCode,omitempty"`
}

type SIpInfo struct {
	Country         string `json:"srcCountry,omitempty"`
	Province        string `json:"srcProvince,omitempty"`
	City            string `json:"srcCity,omitempty"`
	Organization    string `json:"srcOrganization,omitempty"`
	Network         string `json:"srcNetwork,omitempty"`
	Lng             string `json:"srcLng,omitempty"`
	Lat             string `json:"srcLat,omitempty"`
	TimeZone        string `json:"srcTimeZone,omitempty"`
	UTC             string `json:"srcUTC,omitempty"`
	RegionalismCode string `json:"srcRegionalismCode,omitempty"`
	PhoneCode       string `json:"srcPhoneCode,omitempty"`
	CountryCode     string `json:"srcCountryCode,omitempty"`
	ContinentCode   string `json:"srcContinentCode,omitempty"`
}

type DIpInfo struct {
	Country         string `json:"destCountry,omitempty"`
	Province        string `json:"destProvince,omitempty"`
	City            string `json:"destCity,omitempty"`
	Organization    string `json:"destOrganization,omitempty"`
	Network         string `json:"destNetwork,omitempty"`
	Lng             string `json:"destLng,omitempty"`
	Lat             string `json:"destLat,omitempty"`
	TimeZone        string `json:"destTimeZone,omitempty"`
	UTC             string `json:"destUTC,omitempty"`
	RegionalismCode string `json:"destRegionalismCode,omitempty"`
	PhoneCode       string `json:"destPhoneCode,omitempty"`
	CountryCode     string `json:"destCountryCode,omitempty"`
	ContinentCode   string `json:"destContinentCode,omitempty"`
}
