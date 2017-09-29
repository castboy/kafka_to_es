package modules

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var dbHdl *sql.DB

var xdrField = []string{"id", "vendor", "xdr_id", "ipv4", "class",
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
	"cc_floc_tbnam", "cc_floc_sgnt", "alert_type", "alert_id", "xdr_details", "offline_tag", "task_id"}

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

func vdsAlertSql(alert VdsAlert) string {
	sql := fmt.Sprintf(`insert into %s (log_time, threatname, subfile, 
		local_threatname, local_vtype, local_platfrom, local_vname, 
		local_extent, local_enginetype,local_logtype, local_engineip, 
		sourceip, destip, sourceport, destport, app_file, http_url) 
		values (%d, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 
		'%s', '%s', '%s', '%s', %d, %d, '%s', '%s')`,
		"alert_vds", 0, alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", 0, 0, "", "")

	return sql
}

func xdrSql() {
	sql := ""
	for _, v := range xdrField {
		sql = sql + v + ","
	}
	sql = sql[:len(sql)]

	sql = fmt.Sprintf(`insert into %s (%s)`, "xdr", sql)
	fmt.Println(sql)
}

func vdsAlert(sql string) {
	stmt, err := dbHdl.Prepare(sql)
	if err != nil {
		log.Fatal(err)
	}

	defer stmt.Close()

	_, err = stmt.Exec()
	if err != nil {
		log.Fatal(err)
	}
}
