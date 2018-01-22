package modules

type IdsAlert struct {
	Time         uint64
	Src_ip       string
	Src_ip_info  IpInfo
	Src_port     uint16
	Dest_ip      string
	Dest_ip_info IpInfo
	Dest_port    uint16
	Proto        uint8
	Byzoro_type  string
	Attack       string
	Attack_type  string
	Details      string
	Severity     uint32
	Engine       string

	Xdr []BackendObjIds
}

type IdsAlertEs struct {
	TimeAppend     string
	Type           string
	Attack         string
	Byzoro_type    string
	Attack_type    string
	Details        string
	Severity       string
	SeverityAppend string
	Engine         string

	Xdr []BackendObjIds
}

type BackendObjIds struct {
	TimeAppend string
	Conn       Conn_backend `json:Conn`
}

type WafAlert struct {
	Client         string
	Rev            string
	Msg            string
	Attack         string
	Severity       int32
	SeverityAppend string
	Maturity       int32
	Accuracy       int32
	Hostname       string
	Uri            string
	Unique_id      string
	Ref            string
	Tags           []string
	Rule           WafAlertRule
	Version        string
	Type           string
	TimeAppend     string
	Xdr            []BackendObj
}

type VdsAlert struct {
	Subfile          string
	Threatname       string
	Local_threatname string
	Local_vtype      string
	Attack           string
	Local_platfrom   string
	Local_vname      string
	Local_extent     string
	SeverityAppend   string
	Local_enginetype string
	Local_logtype    string
	Local_engineip   string
	Type             string
	TimeAppend       string
	Xdr              []BackendObj
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
	Vendor      string `json:Verdor`
	Id          uint64 `json:id`
	Ipv4        bool   `json:Ipv4`
	Class       uint8  `json:Class`
	Type        uint32 `json:Type`
	Time        uint64 `json:Time`
	TimeAppend  string
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
		State      uint16 `json:"State"`
		UserCount  uint64 `json:"UserCount"`
		CurrentDir string `json:"CurrentDir"`
		TransMode  uint8  `json:"TransMode"`
		TransType  uint8  `json:"TransType"`
		FileCount  uint64 `json:"FileCount"`
		FileSize   uint32 `json:"FileSize"`
		RspTm      uint64 `json:"RspTm"`
		TransTm    uint64 `json:"TransTm"`
	} `json:"Ftp,omitempty"`
	Mail struct {
		MsgType     uint16 `json:"MsgType"`
		RspState    uint16 `json:"RspState"`
		UserName    string `json:"UserName"`
		RecverInfo  string `json:"RecverInfo"`
		Len         uint32 `json:"Len"`
		DomainInfo  string `json:"DomainInfo"`
		RecvAccount string `json:"RecvAccount"`
		Hdr         string `json:"Hdr"`
		AcsType     uint8  `json:"AcsType"`
	} `json:"Mail,omitempty"`
	Dns struct {
		Domain    string   `json:"Domain"`
		IpCount   uint8    `json:"IpCount"`
		IpVersion uint8    `json:"IpVersion"`
		Ip        string   `json:"Ip"`
		IpInfo    IpInfo   `json:"IpInfo"`
		Ips       []string `json:"Ips"`
		IpInfos   []IpInfo `json:"IpInfos"`
		//Ipv4             string   `json:Ipv4`
		//Ipv6             string   `json:Ipv6`
		RspCode          uint8  `json:"RspCode"`
		ReqCount         uint8  `json:"ReqCount"`
		RspRecordCount   uint8  `json:"RspRecordCount"`
		AuthCnttCount    uint8  `json:"AuthCnttCount"`
		ExtraRecordCount uint8  `json:"ExtraRecordCount"`
		RspDelay         uint32 `json:"RspDelay"`
		PktValid         bool   `json:"PktValid"`
	} `json:"Dns"`
	Vpn struct {
		Type uint64 `json:"Type"`
	} `json:"Vpn,omitempty"`
	Proxy struct {
		Type uint64 `json:"Type"`
	} `json:"Proxy,omitempty"`
	QQ struct {
		Number string `json:"Number"`
	} `json:"QQ,omitempty"`
	App struct {
		ProtoInfo    uint64 `json:"ProtoInfo"`
		Status       uint64 `json:"Status"`
		ClassId      uint64 `json:"ClassId"`
		Proto        uint64 `json:"Proto"`
		file         []byte
		File         string       `json:"File"`
		FileLocation LocationHdfs `json:"FileLocation"`
	} `json:"App,omitempty"`
	Ssl struct {
		FailReason uint32    `json:"FailReason"`
		Server     CertsLink `json:"Server"`
		Client     CertsLink `json:"Client"`
	}
}

type Conn_backend struct {
	Proto       uint8 `json:Proto`
	ProtoAppend string
	Sport       uint16 `json:Sport`
	Dport       uint16 `json:Dport`
	Sip         string `json:Sip`
	SipInfo     IpInfo `json:SipInfo`
	Dip         string `json:Dip`
	DipInfo     IpInfo `json:DipInfo`
}

type CertsLink struct {
	Verfy           bool       `json:"Verfy"`
	VerfyFailedDesc string     `json:"VerfyFailedDesc"`
	VerfyFailedIdx  uint32     `json:"VerfyFailedIdx"`
	Cert            CertInfo   `json:"Cert"`
	Certs           []CertInfo `json:"Certs"`
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
	Data                 []byte `json:"Cert"`
}

type LocationHdfs struct {
	Signature string
	Size      int
	Offset    int64
	File      string
	ReqCont   string
	ResCont   string
}

type WafAlertRule struct {
	Ver  string
	Data string
	File string
	Line uint64
	Id   uint64
}

type mysqlLocation struct {
	DbName    string
	TableName string
	Signature string
}

type IpInfo struct {
	Country         string `json:"Country"`
	Province        string `json:"Province"`
	City            string `json:"City"`
	Organization    string `json:"Organization"`
	Network         string `json:"Network"`
	Lng             string `json:"Lng"`
	Lat             string `json:"Lat"`
	TimeZone        string `json:"TimeZone"`
	UTC             string `json:"UTC"`
	RegionalismCode string `json:"RegionalismCode"`
	PhoneCode       string `json:"PhoneCode"`
	CountryCode     string `json:"CountryCode"`
	ContinentCode   string `json:"ContinentCode"`
}
