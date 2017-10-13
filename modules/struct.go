package modules

type IdsAlert struct {
	Time        uint64 `json:Time`
	Src_ip      string `json:"Src_ip"`
	Src_port    uint32 `json:"Src_port"`
	Dest_ip     string `json:"Src_ip"`
	Dest_port   uint32 `json:"Src_port"`
	Proto       uint32 `json:"Proto"`
	Byzoro_type string `json:"Byzoro_type"`
	Attack_type string `json:"Attack_type"`
	Details     string `json:"Details"`
	Severity    uint32 `json:"Severity"`
	Engine      string `json:"engine"`
}

type WafAlert struct {
	Client    string       `json:"Client"`
	Rev       string       `json:"Rev"`
	Msg       string       `json:"Msg"`
	Attack    string       `json:"Attack"`
	Severity  int32        `json:"Severity"`
	Maturity  int32        `json:"Maturity"`
	Accuracy  int32        `json:"Accuracy"`
	Hostname  string       `json:"Hostname"`
	Uri       string       `json:"Uri"`
	Unique_id string       `json:"Unique_id"`
	Ref       string       `json:"Ref"`
	Tags      []string     `json:"Tags"`
	Rule      WafAlertRule `json:"Rule"`
	Version   string       `json:"Version"`
	Xdr       []BackendObj `json:"xdr"`
}

type VdsAlert struct {
	Log_time         int          `json:"Log_time"`
	Threatname       string       `json:"Threatname"`
	Local_threatname string       `json:"Local_threatname"`
	Local_vtype      string       `json:"Local_vtype"`
	Local_platfrom   string       `json:"Local_platfrom"`
	Local_vname      string       `json:"Local_vname"`
	Local_extent     string       `json:"Local_extent"`
	Local_enginetype string       `json:"Local_enginetype"`
	Local_logtype    string       `json:"Local_logtype"`
	Local_engineip   string       `json:"Local_engineip"`
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
		Ips       []string `json:"Ips,omitempty"`
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
	Proto uint8  `json:Proto`
	Sport uint16 `json:Sport`
	Dport uint16 `json:Dport`
	Sip   string `json:Sip`
	Dip   string `json:Dip`
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
	Ver  string `json:"Ver"`
	Data string `json:"Data"`
	File string `json:"File"`
	Line uint64 `json:"Line"`
	Id   uint64 `json:"Id"`
}

type mysqlLocation struct {
	DbName    string
	TableName string
	Signature string
}
