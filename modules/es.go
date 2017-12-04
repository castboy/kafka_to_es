package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	elastic "gopkg.in/olivere/elastic.v5"
)

var attackTypeFormat = map[string]string{
	"disclosure":          "信息泄露",
	"ddos":                "拒绝服务",
	"reputation_ip":       "黑名单匹配",
	"lfi":                 "路径穿越",
	"sqli":                "SQL注入",
	"xss":                 "XSS攻击",
	"injection_php":       "PHP注入",
	"generic":             "异常访问",
	"rce":                 "远程命令",
	"protocol":            "协议攻击",
	"rfi":                 "远程文件注入",
	"fixation":            "会话固定",
	"privilege_gain":      "提权",
	"web_attack":          "Web攻击",
	"application_attack":  "应用程序攻击",
	"candc":               "命令和控制",
	"malware":             "恶意软件",
	"misc_attack":         "杂项攻击",
	"backdoor":            "后门",
	"trojan":              "木马",
	"spyware":             "间谍软件",
	"virus":               "感染型病毒",
	"worm":                "蠕虫",
	"hacktool":            "黑客工具",
	"exploit":             "漏洞利用",
	"webshell":            "webshell",
	"exceptionalvisit":    "异常访问",
	"abnormal_connection": "异常连接",
	"scaning":             "扫描探测",
	"other":               "其他",
}

var client *elastic.Client

func initCli() {
	var err error
	client, err = elastic.NewClient(elastic.SetURL("http://" + esNode + ":" + port))

	if err != nil {
		log.Fatal("can not conn es")
	}
}

func attackMerge(alert interface{}) interface{} {
	switch rt := alert.(type) {
	case IdsAlert:
		switch attackFormat(rt.Byzoro_type) {
		case "DOS", "DDOS", "dos", "ddos", "Dos", "DDos":
			rt.Byzoro_type = "ddos"
		case "scaningprobe", "reputation_scanner", "repitation_scripting", "reputation_crawler":
			rt.Byzoro_type = "scaning"
		default:
		}

		return rt
	case WafAlert:
		switch attackFormat(rt.Attack) {
		case "DOS", "DDOS", "dos", "ddos", "Dos", "DDos":
			rt.Attack = "ddos"
		case "scaningprobe", "reputation_scanner", "repitation_scripting", "reputation_crawler":
			rt.Attack = "scaning"
		default:
		}

		return rt
	case VdsAlert:
		switch attackFormat(rt.Local_vtype) {
		case "DOS", "DDOS", "dos", "ddos", "Dos", "DDos":
			rt.Local_vtype = "ddos"
		case "scaningprobe", "reputation_scanner", "repitation_scripting", "reputation_crawler":
			rt.Local_vtype = "scaning"
		default:
		}

		return rt
	default:
	}

	return nil
}

func parseAlert(msg []byte, alertType string) (interface{}, error) {
	switch alertType {
	case "ids":
		var alert IdsAlert
		err := json.Unmarshal(msg, &alert)
		return alert, err
	case "waf":
		var alert WafAlertObj
		err := json.Unmarshal(msg, &alert)
		return alert.Alert, err
	case "vds":
		var alert VdsAlertObj
		err := json.Unmarshal(msg, &alert)
		return alert.Alert, err
	}

	return nil, errors.New("alert type err")
}

func parseXdr(msg []byte) (BackendObj, error) {
	var xdr BackendObj
	err := json.Unmarshal(msg, &xdr)

	return xdr, err
}

func parseXdrAlert(bytes []byte, alertType string) (interface{}, BackendObj, error) {
	alert, alertErr := parseAlert(bytes, alertType)
	alert = attackMerge(alert)
	xdr, xdrErr := parseXdr(bytes)
	if nil == alertErr && nil == xdrErr {
		return alert, xdr, nil
	}

	return nil, BackendObj{}, errors.New("parseXdrAlert Err")
}

func esObj(msg []byte, alert interface{}, xdr BackendObj) interface{} {
	var xdrSlice = make([]BackendObj, 0)
	xdrSlice = append(xdrSlice, xdr)
	switch rt := alert.(type) {
	case VdsAlert:
		alert = alertVds(&rt, xdrSlice)
	case WafAlert:
		alert = alertWaf(&rt, xdrSlice)
	case IdsAlert:
		alert = alertIds(&rt)
	}

	return alert
}

func alertVds(v *VdsAlert, s []BackendObj) VdsAlert {
	v.SeverityAppend = severityVds(v.Local_extent)
	v.Xdr = s
	v.Type = "vds"

	if t, ok := attackTypeFormat[v.Local_vtype]; ok {
		v.Attack = t
	} else {
		v.Attack = attackTypeFormat["other"]
	}

	for k, val := range v.Xdr {
		v.Xdr[k].TimeAppend = timeFormat(val.Time)
		v.TimeAppend = v.Xdr[k].TimeAppend
		v.Xdr[k].Conn.ProtoAppend = protoFormat(val.Conn.Proto)
	}

	return *v
}

func alertWaf(v *WafAlert, s []BackendObj) WafAlert {
	v.SeverityAppend = severityWaf(v.Severity)
	v.Xdr = s
	v.Type = "waf"

	if t, ok := attackTypeFormat[v.Attack]; ok {
		v.Attack = t
	} else {
		v.Attack = attackTypeFormat["other"]
	}

	for k, val := range v.Xdr {
		v.Xdr[k].TimeAppend = timeFormat(val.Time)
		v.TimeAppend = v.Xdr[k].TimeAppend
		v.Xdr[k].Conn.ProtoAppend = protoFormat(val.Conn.Proto)
	}

	return *v
}

func alertIds(i *IdsAlert) IdsAlertEs {
	var h IdsAlertEs

	h.SeverityAppend = severityIds(i.Severity)
	h.Type = "ids"
	t := timeFormat(i.Time)
	h.TimeAppend = t
	p := protoFormat(i.Proto)
	if t, ok := attackTypeFormat[i.Byzoro_type]; ok {
		h.Attack = t
	} else {
		h.Attack = attackTypeFormat["other"]
	}

	xdr := BackendObjIds{
		TimeAppend: t,
		Conn: Conn_backend{
			Proto:       i.Proto,
			ProtoAppend: p,
			Sip:         i.Src_ip,
			Sport:       i.Src_port,
			SipInfo:     i.Src_ip_info,
			Dip:         i.Dest_ip,
			Dport:       i.Dest_port,
			DipInfo:     i.Dest_ip_info,
		},
	}

	h.Xdr = append(h.Xdr, xdr)

	return h
}

func severityWaf(s int32) string {
	switch s {
	case 0, 1, 2:
		return "高"
	case 3, 4:
		return "中"
	case 5, 6, 7:
		return "低"
	default:
		panic("wrong waf severity")
	}
}

func severityIds(s uint32) string {
	switch s {
	case 0, 1, 2:
		return "高"
	case 3, 4:
		return "中"
	case 5, 6, 7:
		return "低"
	default:
		panic("wrong waf severity")
	}
}

func severityVds(s string) string {
	switch s {
	case "High":
		return "高"
	case "Medium":
		return "中"
	case "Low":
		return "低"
	default:
		panic("wrong vds severity")
	}
}

func timeFormat(t uint64) string {
	tp := t / 1000000
	tm := time.Unix(int64(tp), 0)

	return tm.Format("2006-01-02 03:04:05")
}

func protoFormat(p uint8) string {
	if 6 == p {
		return "tcp"
	}

	return "udp"
}

func attackFormat(s string) string {
	if match, _ := regexp.MatchString("attack-.*", s); match {
		return s[7:]
	}

	return s
}

func addEs(topic string, obj interface{}) {
	ctx := context.Background()

	_, err := client.Index().
		Index("apt").
		Type(esType(topic)).
		BodyJson(obj).
		Do(ctx)
	if err != nil {
		Log("ERR", "to es %s", esType(topic))
	} else {
		Log("INF", "success to es %s", esType(topic))
	}
}

func esType(topic string) string {
	switch topic {
	case "waf-alert":
		return "waf_alert"
	case "vds-alert":
		return "vds_alert"
	case "ids-alert":
		return "ids_alert"
	}

	return ""
}

func toEs(msg []byte, alert interface{}, xdr BackendObj, topic string) {
	obj := esObj(msg, alert, xdr)
	bytes, _ := json.Marshal(obj)
	fmt.Println(string(bytes))
	addEs(topic, obj)
}
