package modules

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

var dbHdl *sql.DB

var xdrField = []string{"vendor", "xdr_id", "ipv4", "class",
	"type", "time", "conn_proto", "conn_sport", "conn_dport",
	"conn_sip", "conn_scountry", "conn_sprovince", "conn_sorg", "conn_snetwork",
	"conn_slng", "conn_slat", "conn_stimezone", "conn_sutc", "conn_sregioncode", "conn_sphonecode",
	"conn_scountrycode", "conn_scontinentcode", "conn_dip", "conn_dcountry", "conn_dprovince", "conn_dorg", "conn_dnetwork",
	"conn_dlng", "conn_dlat", "conn_dtimezone", "conn_dutc", "conn_dregioncode", "conn_dphonecode",
	"conn_dcountrycode", "conn_dcontinentcode", "cex_over", "cex_dir", "cst_flup",
	"cst_fld", "cst_pktup", "cst_pktd", "cst_ipfragup", "cst_ipfragd",
	"ctime_start", "ctime_end", "sst_flup", "sst_fld", "sst_pktup",
	"sst_pktd", "sst_ipfragup", "sst_ipfragd", "sst_tcpdsodup", "sst_tcpdsodd",
	"sst_tcpretrup", "sst_tcpretrd", "tcp_dsodup", "tcp_dsodd", "tcp_retranup",
	"tcp_retrand", "tcp_synackdly", "tcp_ackdelay", "tcp_rportflag", "tcp_clsresn",
	"tcp_fstreqdly", "tcp_fstrepdly", "tcp_window", "tcp_mss", "tcp_syncount",
	"tcp_synackcont", "tcp_ackcount", "tcp_sesionok", "tcp_hndshk12", "tcp_hndshk23",
	"tcp_open", "tcp_close", "http_host", "http_country", "http_province", "http_org", "http_network",
	"http_lng", "http_lat", "http_timezone", "http_utc", "http_regioncode", "http_phonecode",
	"http_countrycode", "http_continentcode", "http_url", "http_xolhost",
	"http_usragnt", "http_cnttype", "http_refer", "http_cookie", "http_loction",
	"http_request", "http_reqlfile", "http_reqlofst", "http_reqlsize", "http_reqlsgnt",
	"http_response", "http_rsplfile", "http_rsplofst", "http_rsplsize", "http_rsplsgnt",
	"http_reqtime", "http_fstrsptm", "http_lstcnttm", "http_servtime", "http_cntntlen",
	"http_statcode", "http_method", "http_version", "http_headflag", "http_servflag",
	"http_reqflag", "http_browser", "http_portal", "sip_callingno", "sip_calledno",
	"sip_sessionid", "sip_calldir", "sip_calltype", "sip_hngupresn", "sip_signaltype",
	"sip_strmcount", "sip_malloc", "sip_bye", "sip_invite", "rtsp_Url",
	"rtsp_usragent", "rtsp_serverip", "rtsp_clibgnport", "rtsp_cliendport", "rtsp_servbgnport",
	"rtsp_servendport", "rtsp_vdostrmcnt", "rtsp_adostrmcnt", "rtsp_resdelay", "ftp_state",
	"ftp_usrcount", "ftp_currentdir", "ftp_transmode", "ftp_transtype", "ftp_filecount",
	"ftp_filesize", "ftp_rsptm", "ftp_transtm", "mail_msgtype", "mail_rspstate",
	"mail_usrname", "mail_recvinfo", "mail_len", "mail_domninfo", "mail_recvacont",
	"mail_hdr", "mail_acstype", "dns_domain", "dns_ipcount", "dns_ipver",
	"dns_ip", "dns_country", "dns_province", "dns_org", "dns_network",
	"dns_lng", "dns_lat", "dns_timezone", "dns_utc", "dns_regioncode", "dns_phonecode",
	"dns_countrycode", "dns_continentcode", "dns_ips", "dns_rspcode", "dns_rspcount", "dns_rsprcdcnt",
	"dns_authcntcnt", "dns_xtrrcdcnt", "dns_rspdelay", "dns_pktvalid", "vpn_type",
	"proxy_type", "qq_num", "app_protoinf", "app_status", "app_classid",
	"app_proto", "app_file", "app_flocfile", "app_flocofst", "app_flocsize",
	"app_flocsgnt", "ssl_failresn", "serv_vfy", "serv_vfyflddsc", "serv_vfyfldidx",
	"scert_ver", "scert_srlnum", "scert_nbef", "scert_naft", "scert_kusg",
	"scert_cntrnam", "scert_ognznam", "scert_ognzunam", "scert_comnnam", "sc_floc_dbnam",
	"sc_floc_tbnam", "sc_floc_sgnt", "cli_vfy", "cli_vfyflddsc", "cli_vfyfldidx",
	"ccert_ver", "ccert_srlnum", "ccert_nbef", "ccert_naft", "ccert_kusg",
	"ccert_cntrnam", "ccert_ognznam", "ccert_ognzunam", "ccert_comnnam", "cc_floc_dbnam",
	"cc_floc_tbnam", "cc_floc_sgnt", "alert_type", "alert_id", "xdr_details"}

func Mysql() {
	user, pwd, host, port, db := mysqlConf()
	database(user, pwd, host, port, db)
}

func mysqlConf() (user, pwd, host, port, db string) {
	host = conf.GetValue("mysql", "host")
	port = conf.GetValue("mysql", "port")
	user = conf.GetValue("mysql", "user")
	pwd = conf.GetValue("mysql", "passwd")
	db = conf.GetValue("mysql", "db")

	return user, pwd, host, port, db
}

func database(usr, pwd, host, port, db string) {
	var err error

	connParams := usr + ":" + pwd + "@tcp(" + host + ":" + port + ")/" + db
	dbHdl, err = sql.Open("mysql", connParams)
	if err != nil {
		log.Fatal(err)
	}

	err = dbHdl.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func boolToInt(v bool) int {
	var i int
	if v == false {
		i = 0
	} else {
		i = 1
	}

	return i
}

func vdsAlertSql(alert VdsAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, threatname, subfile,
		local_threatname, local_vtype, local_platfrom, local_vname,
		local_extent, local_enginetype,local_logtype, local_engineip,
		src_ip, dest_ip, src_port, dest_port, app_file, http_url,
		src_country, src_province, src_city, src_latitude, src_longitude,
		dest_country, dest_province, dest_city, dest_latitude, dest_longitude)
		values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, '%s', '%s',
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`,
		"alert_vds", xdr.Time, alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", 0, 0, "", "",
		xdr.Conn.SipInfo.Country, xdr.Conn.SipInfo.Province, xdr.Conn.SipInfo.City, xdr.Conn.SipInfo.Lat, xdr.Conn.SipInfo.Lng,
		xdr.Conn.DipInfo.Country, xdr.Conn.DipInfo.Province, xdr.Conn.DipInfo.City, xdr.Conn.DipInfo.Lat, xdr.Conn.DipInfo.Lng)

	return sql
}

func vdsOfflineAlertSql(alert VdsAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, threatname, subfile,
		local_threatname, local_vtype, local_platfrom, local_vname,
		local_extent, local_enginetype,local_logtype, local_engineip,
		src_ip, dest_ip, src_port, dest_port, app_file, http_url,
		src_country, src_province, src_city, src_latitude, src_longitude,
		dest_country, dest_province, dest_city, dest_latitude, dest_longitude)
		values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, '%s', '%s',
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`,
		"alert_vds_offline", xdr.Time, alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", 0, 0, "", "",
		xdr.Conn.SipInfo.Country, xdr.Conn.SipInfo.Province, xdr.Conn.SipInfo.City, xdr.Conn.SipInfo.Lat, xdr.Conn.SipInfo.Lng,
		xdr.Conn.DipInfo.Country, xdr.Conn.DipInfo.Province, xdr.Conn.DipInfo.City, xdr.Conn.DipInfo.Lat, xdr.Conn.DipInfo.Lng)

	return sql
}

func wafAlertSql(alert WafAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, client, rev, msg, attack,
		severity, maturity, accuracy, hostname, uri, unique_id, ref, tags,
		rule_file, rule_line, rule_id, rule_data, rule_ver, version,
		src_country, src_province, src_city, src_latitude, src_longitude,
		dest_country, dest_province, dest_city, dest_latitude, dest_longitude) 
		values (%d, '%s', '%s', '%s', '%s', %d, %d, %d, '%s', '%s', '%s', 
		'%s', '%s', '%s', %d, %d, '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`,
		"alert_waf", xdr.Time, alert.Client, alert.Rev, alert.Msg, alert.Attack,
		alert.Severity, alert.Maturity, alert.Accuracy, alert.Hostname,
		alert.Uri, alert.Unique_id, alert.Ref, alert.Tags, "", 0, 0, "", "",
		alert.Version,
		xdr.Conn.SipInfo.Country, xdr.Conn.SipInfo.Province, xdr.Conn.SipInfo.City, xdr.Conn.SipInfo.Lat, xdr.Conn.SipInfo.Lng,
		xdr.Conn.DipInfo.Country, xdr.Conn.DipInfo.Province, xdr.Conn.DipInfo.City, xdr.Conn.DipInfo.Lat, xdr.Conn.DipInfo.Lng)

	return sql
}

func wafOfflineAlertSql(alert WafAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, client, rev, msg, attack,
		severity, maturity, accuracy, hostname, uri, unique_id, ref, tags,
		rule_file, rule_line, rule_id, rule_data, rule_ver, version,
		src_country, src_province, src_city, src_latitude, src_longitude,
		dest_country, dest_province, dest_city, dest_latitude, dest_longitude) 
		values (%d, '%s', '%s', '%s', '%s', %d, %d, %d, '%s', '%s', '%s', 
		'%s', '%s', '%s', %d, %d, '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`,
		"alert_waf_offline", xdr.Time, alert.Client, alert.Rev, alert.Msg, alert.Attack,
		alert.Severity, alert.Maturity, alert.Accuracy, alert.Hostname,
		alert.Uri, alert.Unique_id, alert.Ref, alert.Tags, "", 0, 0, "", "",
		alert.Version,
		xdr.Conn.SipInfo.Country, xdr.Conn.SipInfo.Province, xdr.Conn.SipInfo.City, xdr.Conn.SipInfo.Lat, xdr.Conn.SipInfo.Lng,
		xdr.Conn.DipInfo.Country, xdr.Conn.DipInfo.Province, xdr.Conn.DipInfo.City, xdr.Conn.DipInfo.Lat, xdr.Conn.DipInfo.Lng)

	return sql
}

func idsAlertSql(alert IdsAlert) string {
	sql := fmt.Sprintf(`insert into %s (time, src_ip, src_port, dest_ip,
		dest_port, proto, attack_type, details, severity, engine, byzoro_type,
		src_country, src_province, src_city, src_latitude, src_longitude,
		dest_country, dest_province, dest_city, dest_latitude, dest_longitude) 
		values (%d, '%s', %d, '%s', %d, '%s', '%s', '%s', %d, '%s', '%s',
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')`, "alert_ids",
		alert.Time, alert.Src_ip, alert.Src_port, alert.Dest_ip, alert.Dest_port,
		alert.Proto, alert.Attack_type, alert.Details, alert.Severity, alert.Engine,
		alert.Byzoro_type,
		"", "", "", "", "",
		"", "", "", "", "")

	return sql
}

func xdrSql(x BackendObj, id int64, t string) string {
	sql := ""
	for _, v := range xdrField {
		sql = sql + v + ","
	}
	sql = sql[:len(sql)-1]

	sql = fmt.Sprintf(`insert into %s (%s) values (
		'%s', %d, %d, %d, %d, %d,
		'%s', %d, %d, '%s', 
		'%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s',
		'%s',
		'%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s',
		%d, %d,
		%d, %d, %d, %d, %d, %d,
		%d, %d,
		%d, %d, %d, %d, %d, %d, %d, %d, %d, %d,
		%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,
		'%s', 
		'%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s', '%s', 
		%d, %d, '%s', '%s', '%s', 
		%d, '%d', '%s', %d, %d, 
		%d, %d, %d, %d, %d, 
		%d, %d, %d, %d, %d, %d,
		'%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d, %d,
		'%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d,
		%d, %d, '%s', %d, %d, %d, %d, %d, %d,
		%d, %d, '%s', '%s', %d, '%s', '%s', '%s', %d,
		'%s', %d, %d, '%s', 
		'%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s',		
		'%s', %d, %d, %d, %d, %d, %d, %d,
		%d, %d, '%s',
		%d, %d, %d, %d, '%s', '%s', %d, %d, '%s',
		%d, %d, '%s', %d, %d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s',
		'%s', '%s', '%s',
		%d, '%s', %d,
		%d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s',
		'%s', '%s', '%s',
		'%s', %d, '%s'
		)`, "xdr", sql,
		x.Vendor, x.Id, boolToInt(x.Ipv4), x.Class, x.Type, x.Time,
		strconv.Itoa(int(x.Conn.Proto)), x.Conn.Sport, x.Conn.Dport, x.Conn.Sip,
		x.Conn.SipInfo.Country, x.Conn.SipInfo.Province, x.Conn.SipInfo.Organization, x.Conn.SipInfo.Network,
		x.Conn.SipInfo.Lng, x.Conn.SipInfo.Lat, x.Conn.SipInfo.TimeZone, x.Conn.SipInfo.UTC,
		x.Conn.SipInfo.RegionalismCode, x.Conn.SipInfo.PhoneCode, x.Conn.SipInfo.CountryCode, x.Conn.SipInfo.ContinentCode,
		x.Conn.Dip,
		x.Conn.DipInfo.Country, x.Conn.DipInfo.Province, x.Conn.DipInfo.Organization, x.Conn.DipInfo.Network,
		x.Conn.DipInfo.Lng, x.Conn.DipInfo.Lat, x.Conn.DipInfo.TimeZone, x.Conn.DipInfo.UTC,
		x.Conn.DipInfo.RegionalismCode, x.Conn.DipInfo.PhoneCode, x.Conn.DipInfo.CountryCode, x.Conn.DipInfo.ContinentCode,
		boolToInt(x.ConnEx.Over), boolToInt(x.ConnEx.Dir),
		x.ConnSt.FlowUp, x.ConnSt.FlowDown, x.ConnSt.PktUp, x.ConnSt.PktDown, x.ConnSt.IpFragUp, x.ConnSt.IpFragDown,
		x.ConnTime.Start, x.ConnTime.End,
		x.ServSt.FlowUp, x.ServSt.FlowDown, x.ServSt.PktUp, x.ServSt.PktDown, x.ServSt.IpFragUp, x.ServSt.IpFragDown, x.ServSt.TcpDisorderUp, x.ServSt.TcpDisorderDown, x.ServSt.TcpRetranUp, x.ServSt.TcpRetranDown,
		x.Tcp.DisorderUp, x.Tcp.DisorderDown, x.Tcp.RetranUp, x.Tcp.RetranDown, x.Tcp.SynAckDelay, x.Tcp.AckDelay, x.Tcp.ReportFlag, x.Tcp.CloseReason, x.Tcp.FirstRequestDelay, x.Tcp.FirstResponseDely, x.Tcp.Window, x.Tcp.Mss, x.Tcp.SynCount, x.Tcp.SynAckCount, x.Tcp.AckCount, boolToInt(x.Tcp.SessionOK), boolToInt(x.Tcp.Handshake12), boolToInt(x.Tcp.Handshake23), x.Tcp.Open, x.Tcp.Close,
		x.Http.Host,
		x.Http.HostIpInfo.Country, x.Http.HostIpInfo.Province, x.Http.HostIpInfo.Organization, x.Http.HostIpInfo.Network,
		x.Http.HostIpInfo.Lng, x.Http.HostIpInfo.Lat, x.Http.HostIpInfo.TimeZone, x.Http.HostIpInfo.UTC,
		x.Http.HostIpInfo.RegionalismCode, x.Http.HostIpInfo.PhoneCode, x.Http.HostIpInfo.CountryCode, x.Http.HostIpInfo.ContinentCode,
		x.Http.Url, x.Http.XonlineHost, x.Http.UserAgent, x.Http.ContentType,
		x.Http.Refer, x.Http.Cookie, x.Http.Location, x.Http.request, x.Http.RequestLocation.File,
		x.Http.RequestLocation.Offset, x.Http.RequestLocation.Size, x.Http.RequestLocation.Signature, x.Http.response, x.Http.ResponseLocation.File,
		x.Http.ResponseLocation.Offset, x.Http.ResponseLocation.Size, x.Http.ResponseLocation.Signature, x.Http.RequestTime, x.Http.FirstResponseTime,
		x.Http.LastContentTime, x.Http.ServTime, x.Http.ContentLen, x.Http.StateCode, x.Http.Method,
		x.Http.Version, boolToInt(x.Http.HeadFlag), x.Http.ServFlag, boolToInt(x.Http.RequestFlag), x.Http.Browser, x.Http.Portal,
		x.Sip.CallingNo, x.Sip.CalledNo, x.Sip.SessionId, x.Sip.CallDir, x.Sip.CallType, x.Sip.HangupReason, x.Sip.SignalType, x.Sip.StreamCount, boolToInt(x.Sip.Malloc), boolToInt(x.Sip.Bye), boolToInt(x.Sip.Invite),
		x.Rtsp.Url, x.Rtsp.UserAgent, x.Rtsp.ServerIp, x.Rtsp.ClientBeginPort, x.Rtsp.ClientEndPort, x.Rtsp.ServerBeginPort, x.Rtsp.ServerEndPort, x.Rtsp.VideoStreamCount, x.Rtsp.AudeoStreamCount, x.Rtsp.ResDelay,
		x.Ftp.State, x.Ftp.UserCount, x.Ftp.CurrentDir, x.Ftp.TransMode, x.Ftp.TransType, x.Ftp.FileCount, x.Ftp.FileSize, x.Ftp.RspTm, x.Ftp.TransTm,
		x.Mail.MsgType, x.Mail.RspState, x.Mail.UserName, x.Mail.RecverInfo, x.Mail.Len, x.Mail.DomainInfo, x.Mail.RecvAccount, x.Mail.Hdr, x.Mail.AcsType,
		x.Dns.Domain, x.Dns.IpCount, x.Dns.IpVersion, x.Dns.Ip,
		x.Dns.IpInfo.Country, x.Dns.IpInfo.Province, x.Dns.IpInfo.Organization, x.Dns.IpInfo.Network,
		x.Dns.IpInfo.Lng, x.Dns.IpInfo.Lat, x.Dns.IpInfo.TimeZone, x.Dns.IpInfo.UTC,
		x.Dns.IpInfo.RegionalismCode, x.Dns.IpInfo.PhoneCode, x.Dns.IpInfo.CountryCode, x.Dns.IpInfo.ContinentCode,
		x.Dns.Ips, x.Dns.RspCode, x.Dns.RspRecordCount, x.Dns.RspRecordCount, x.Dns.AuthCnttCount, x.Dns.ExtraRecordCount, x.Dns.RspDelay, boolToInt(x.Dns.PktValid),
		x.Vpn.Type, x.Proxy.Type, x.QQ.Number,
		x.App.ProtoInfo, x.App.Status, x.App.ClassId, x.App.Proto, x.App.File, x.App.FileLocation.File, x.App.FileLocation.Offset, x.App.FileLocation.Size, x.App.FileLocation.Signature,
		x.Ssl.FailReason, boolToInt(x.Ssl.Server.Verfy), x.Ssl.Server.VerfyFailedDesc, x.Ssl.Server.VerfyFailedIdx, x.Ssl.Server.Cert.Version, x.Ssl.Server.Cert.SerialNumber, x.Ssl.Server.Cert.NotBefore, x.Ssl.Server.Cert.NotAfter, x.Ssl.Server.Cert.KeyUsage, x.Ssl.Server.Cert.CountryName, x.Ssl.Server.Cert.OrganizationName, x.Ssl.Server.Cert.OrganizationUnitName, x.Ssl.Server.Cert.CommonName,
		x.Ssl.Server.Cert.FileLocation.DbName, x.Ssl.Server.Cert.FileLocation.TableName, x.Ssl.Server.Cert.FileLocation.Signature,
		boolToInt(x.Ssl.Client.Verfy), x.Ssl.Client.VerfyFailedDesc, x.Ssl.Client.VerfyFailedIdx,
		x.Ssl.Client.Cert.Version, x.Ssl.Client.Cert.SerialNumber, x.Ssl.Client.Cert.NotBefore, x.Ssl.Client.Cert.NotAfter, x.Ssl.Client.Cert.KeyUsage, x.Ssl.Client.Cert.CountryName, x.Ssl.Client.Cert.OrganizationName, x.Ssl.Client.Cert.OrganizationUnitName, x.Ssl.Client.Cert.CommonName,
		x.Ssl.Client.Cert.FileLocation.DbName, x.Ssl.Client.Cert.FileLocation.TableName, x.Ssl.Client.Cert.FileLocation.Signature,
		t, id, "")

	fmt.Println(sql)
	return sql
}

func query(sql string) sql.Result {
	stmt, err := dbHdl.Prepare(sql)
	if err != nil {
		log.Fatal(err)
	}

	defer stmt.Close()

	rs, err := stmt.Exec()
	if err != nil {
		log.Fatal(err)
	}

	return rs
}

func vdsToMysql(alert VdsAlert, topic string, xdr BackendObj, alertType string) {
	res := vdsAlertToMysql(alert, xdr)
	xdrToMysql(res, xdr, alertType)
	fmt.Println("vdsToMysql success")
}

func wafToMysql(alert WafAlert, topic string, xdr BackendObj, alertType string) {
	res := wafAlertToMysql(alert, xdr)
	xdrToMysql(res, xdr, alertType)
	fmt.Println("wafToMysql success")
}

func isOffline(xdr BackendObj) bool {
	if "" == xdr.Task_Id {
		return false
	}

	return true
}

func vdsAlertToMysql(alert VdsAlert, xdr BackendObj) sql.Result {
	sql := ""
	if isOffline(xdr) {
		sql = vdsOfflineAlertSql(alert, xdr)
	} else {
		sql = vdsAlertSql(alert, xdr)
	}
	return query(sql)
}

func wafAlertToMysql(alert WafAlert, xdr BackendObj) sql.Result {
	sql := ""
	if isOffline(xdr) {
		sql = wafOfflineAlertSql(alert, xdr)
	} else {
		sql = wafAlertSql(alert, xdr)
	}
	return query(sql)
}

func xdrToMysql(alertToMysqlRes sql.Result, xdr BackendObj, alertType string) {
	id, err := alertToMysqlRes.LastInsertId()
	if nil != err {
		log.Fatalf("can not get waf-alert id")
	}
	query(xdrSql(xdr, id, alertType))
}

func idsToMysql(alert IdsAlert) {
	query(idsAlertSql(alert))
	fmt.Println("idsToMysql success")
}

func toMysql(alert interface{}, xdr BackendObj, topic string, alertType string) {
	switch Alert := alert.(type) {
	case VdsAlert:
		fmt.Println(Alert)
		vdsToMysql(Alert, topic, xdr, alertType)
	case WafAlert:
		wafToMysql(Alert, topic, xdr, alertType)
		fmt.Println(Alert)
	case IdsAlert:
		idsToMysql(Alert)
		fmt.Println(Alert)
	}
	fmt.Println("toMysql")
}
