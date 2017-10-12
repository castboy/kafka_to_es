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
	"conn_sip", "conn_dip", "cex_over", "cex_dir", "cst_flup",
	"cst_fld", "cst_pktup", "cst_pktd", "cst_ipfragup", "cst_ipfragd",
	"ctime_start", "ctime_end", "sst_flup", "sst_fld", "sst_pktup",
	"sst_pktd", "sst_ipfragup", "sst_ipfragd", "sst_tcpdsodup", "sst_tcpdsodd",
	"sst_tcpretrup", "sst_tcpretrd", "tcp_dsodup", "tcp_dsodd", "tcp_retranup",
	"tcp_retrand", "tcp_synackdly", "tcp_ackdelay", "tcp_rportflag", "tcp_clsresn",
	"tcp_fstreqdly", "tcp_fstrepdly", "tcp_window", "tcp_mss", "tcp_syncount",
	"tcp_synackcont", "tcp_ackcount", "tcp_sesionok", "tcp_hndshk12", "tcp_hndshk23",
	"tcp_open", "tcp_close", "http_host", "http_url", "http_xolhost",
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
	"dns_ip", "dns_ips", "dns_rspcode", "dns_rspcount", "dns_rsprcdcnt",
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
	sql := fmt.Sprintf(`insert into %s (log_time, threatname, subfile,
		local_threatname, local_vtype, local_platfrom, local_vname,
		local_extent, local_enginetype,local_logtype, local_engineip,
		sourceip, destip, sourceport, destport, app_file, http_url)
		values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, '%s', '%s')`,
		"alert_vds", xdr.Time, alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", 0, 0, "", "")

	return sql
}

func vdsOfflineAlertSql(alert VdsAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (log_time, threatname, subfile,
		local_threatname, local_vtype, local_platfrom, local_vname,
		local_extent, local_enginetype,local_logtype, local_engineip,
		sourceip, destip, sourceport, destport, app_file, http_url)
		values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
		'%s', '%s', '%s', '%s', %d, %d, '%s', '%s')`,
		"alert_vds_offline", xdr.Time, alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", 0, 0, "", "")

	return sql
}

func wafAlertSql(alert WafAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, client, rev, msg, attack,
		severity, maturity, accuracy, hostname, uri, unique_id, ref, tags,
		rule_file, rule_line, rule_id, rule_data, rule_ver, version) 
		values (%d, '%s', '%s', '%s', '%s', %d, %d, %d, '%s', '%s', '%s', 
		'%s', '%s', '%s', %d, %d, '%s', '%s', '%s')`,
		"alert_waf", xdr.Time, alert.Client, alert.Rev, alert.Msg, alert.Attack,
		alert.Severity, alert.Maturity, alert.Accuracy, alert.Hostname,
		alert.Uri, alert.Unique_id, alert.Ref, alert.Tags, "", 0, 0, "", "",
		alert.Version)

	return sql
}

func wafOfflineAlertSql(alert WafAlert, xdr BackendObj) string {
	sql := fmt.Sprintf(`insert into %s (time, client, rev, msg, attack,
		severity, maturity, accuracy, hostname, uri, unique_id, ref, tags,
		rule_file, rule_line, rule_id, rule_data, rule_ver, version) 
		values (%d, '%s', '%s', '%s', '%s', %d, %d, %d, '%s', '%s', '%s', 
		'%s', '%s', '%s', %d, %d, '%s', '%s', '%s')`,
		"alert_waf_offline", xdr.Time, alert.Client, alert.Rev, alert.Msg, alert.Attack,
		alert.Severity, alert.Maturity, alert.Accuracy, alert.Hostname,
		alert.Uri, alert.Unique_id, alert.Ref, alert.Tags, "", 0, 0, "", "",
		alert.Version)

	return sql
}

func idsAlertSql(alert IdsAlert) string {
	sql := fmt.Sprintf(`insert into %s (time, src_ip, src_port, dest_ip,
		dest_port, proto, attack_type, details, severity, engine, byzoro_type) 
		values (%d, '%s', %d, '%s', %d, '%s', '%s', '%s', %d, '%s', '%s')`,
		alert.Time, alert.Src_ip, alert.Src_port, alert.Dest_ip, alert.Dest_port,
		alert.Proto, alert.Attack_type, alert.Details, alert.Severity, alert.Engine,
		alert.Byzoro_type)

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
		'%s', %d, %d, '%s', '%s',
		%d, %d,
		%d, %d, %d, %d, %d, %d,
		%d, %d,
		%d, %d, %d, %d, %d, %d, %d, %d, %d, %d,
		%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,
		'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', '%s', '%s', %d, '%d', '%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,
		'%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d, %d,
		'%s', '%s', '%s', %d, %d, %d, %d, %d, %d, %d,
		%d, %d, '%s', %d, %d, %d, %d, %d, %d,
		%d, %d, '%s', '%s', %d, '%s', '%s', '%s', %d,
		'%s', %d, %d, '%s', '%s', %d, %d, %d, %d, %d, %d, %d,
		%d, %d, '%s',
		%d, %d, %d, %d, '%s, '%s', %d, %d, '%s',
		%d, '%s', '%s', %d, %d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s',
		'%s', '%s', '%s',
		%d, '%s', %d,
		%d, '%s', %d, %d, %d, '%s', '%s', '%s', '%s',
		'%s', '%s', '%s',
		'%s', %d, '%s'
		)`, "xdr", sql,
		x.Vendor, x.Id, boolToInt(x.Ipv4), x.Class, x.Type, x.Time,
		strconv.Itoa(int(x.Conn.Proto)), x.Conn.Sport, x.Conn.Dport, x.Conn.Sip, x.Conn.Dip,
		boolToInt(x.ConnEx.Over), boolToInt(x.ConnEx.Dir),
		x.ConnSt.FlowUp, x.ConnSt.FlowDown, x.ConnSt.PktUp, x.ConnSt.PktDown, x.ConnSt.IpFragUp, x.ConnSt.IpFragDown,
		x.ConnTime.Start, x.ConnTime.End,
		x.ServSt.FlowUp, x.ServSt.FlowDown, x.ServSt.PktUp, x.ServSt.PktDown, x.ServSt.IpFragUp, x.ServSt.IpFragDown, x.ServSt.TcpDisorderUp, x.ServSt.TcpDisorderDown, x.ServSt.TcpRetranUp, x.ServSt.TcpRetranDown,
		x.Tcp.DisorderUp, x.Tcp.DisorderDown, x.Tcp.RetranUp, x.Tcp.RetranDown, x.Tcp.SynAckDelay, x.Tcp.AckDelay, x.Tcp.ReportFlag, x.Tcp.CloseReason, x.Tcp.FirstRequestDelay, x.Tcp.FirstResponseDely, x.Tcp.Window, x.Tcp.Mss, x.Tcp.SynCount, x.Tcp.SynAckCount, x.Tcp.AckCount, boolToInt(x.Tcp.SessionOK), boolToInt(x.Tcp.Handshake12), boolToInt(x.Tcp.Handshake23), x.Tcp.Open, x.Tcp.Close,
		x.Http.Host, x.Http.Url, x.Http.XonlineHost, x.Http.UserAgent, x.Http.ContentType, x.Http.Refer, x.Http.Cookie, x.Http.Location, x.Http.request, x.Http.RequestLocation.File, x.Http.RequestLocation.Offset, x.Http.RequestLocation.Size, x.Http.RequestLocation.Signature, x.Http.response, x.Http.ResponseLocation.File, x.Http.ResponseLocation.Offset, x.Http.ResponseLocation.Size, x.Http.ResponseLocation.Signature, x.Http.RequestTime, x.Http.FirstResponseTime, x.Http.FirstResponseTime, x.Http.LastContentTime, x.Http.ServTime, x.Http.ContentLen, x.Http.StateCode, x.Http.Method, x.Http.Version, x.Http.HeadFlag, x.Http.ServFlag, boolToInt(x.Http.RequestFlag), x.Http.Browser, x.Http.Portal,
		x.Sip.CallingNo, x.Sip.CalledNo, x.Sip.SessionId, x.Sip.CallDir, x.Sip.CallType, x.Sip.HangupReason, x.Sip.SignalType, x.Sip.StreamCount, x.Sip.Malloc, boolToInt(x.Sip.Bye), boolToInt(x.Sip.Invite),
		x.Rtsp.UserAgent, x.Rtsp.ServerIp, x.Rtsp.ClientBeginPort, x.Rtsp.ClientEndPort, x.Rtsp.ServerBeginPort, x.Rtsp.ServerEndPort, x.Rtsp.VideoStreamCount, x.Rtsp.AudeoStreamCount, x.Rtsp.ResDelay,
		x.Ftp.State, x.Ftp.UserCount, x.Ftp.CurrentDir, x.Ftp.TransMode, x.Ftp.TransType, x.Ftp.FileCount, x.Ftp.FileSize, x.Ftp.RspTm, x.Ftp.TransTm,
		x.Mail.MsgType, x.Mail.RspState, x.Mail.UserName, x.Mail.RecverInfo, x.Mail.Len, x.Mail.DomainInfo, x.Mail.RecvAccount, x.Mail.Hdr, x.Mail.AcsType,
		x.Dns.Domain, x.Dns.IpCount, x.Dns.IpVersion, x.Dns.Ip, x.Dns.Ips, x.Dns.RspCode, x.Dns.RspRecordCount, x.Dns.RspRecordCount, x.Dns.AuthCnttCount, x.Dns.ExtraRecordCount, x.Dns.RspDelay, boolToInt(x.Dns.PktValid),
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
	fmt.Println("vdsToMysql_______________")
	res := vdsAlertToMysql(alert, xdr)
	xdrToMysql(res, xdr, alertType)
}

func wafToMysql(alert WafAlert, topic string, xdr BackendObj, alertType string) {
	res := wafAlertToMysql(alert, xdr)
	xdrToMysql(res, xdr, alertType)
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
