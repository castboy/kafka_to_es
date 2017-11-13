package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	elastic "gopkg.in/olivere/elastic.v5"
)

func attackMerge(alert interface{}) interface{} {
	switch rt := alert.(type) {
	case IdsAlert:
		switch rt.Attack_type {
		case "DOS", "DDOS":
			rt.Attack_type = "DDOS"
		case "scaningprobe", "reputation_scanner", "repitation_scripting", "reputation_crawler":
			rt.Attack_type = "scaning"
		default:
		}

		return rt
	case WafAlert:
		switch rt.Attack {
		case "DOS", "DDOS":
			rt.Attack = "DDOS"
		case "scaningprobe", "reputation_scanner", "repitation_scripting", "reputation_crawler":
			rt.Attack = "scaning"
		default:
		}

		return rt
	case VdsAlert:
		switch rt.Local_vtype {
		case "DOS", "DDOS":
			rt.Local_vtype = "DDOS"
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
	v.Attack = v.Local_vtype
	v.SeverityAppend = severityVds(v.Local_extent)
	v.Xdr = s

	return *v
}

func alertWaf(v *WafAlert, s []BackendObj) WafAlert {
	v.SeverityAppend = severityWaf(v.Severity)
	v.Xdr = s

	return *v
}

func alertIds(i *IdsAlert) IdsAlert {
	i.Attack = i.Byzoro_type
	i.SeverityAppend = severityIds(i.Severity)

	xdr := BackendObjIds{
		Time: i.Time,
		Conn: Conn_backend{
			Proto:   i.Proto,
			Sip:     i.Src_ip,
			Sport:   i.Src_port,
			SipInfo: i.Src_ip_info,
			Dip:     i.Dest_ip,
			Dport:   i.Dest_port,
			DipInfo: i.Dest_ip_info,
		},
	}

	i.Xdr = append(i.Xdr, xdr)

	return *i
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

func addEs(topic string, obj interface{}) {
	ctx := context.Background()
	client, err := elastic.NewClient(elastic.SetURL("http://10.88.1.102:9200"))
	if err != nil {
		log.Fatal("can not conn es")
	}

	_, err = client.Index().
		Index("apt").
		Type(esType(topic)).
		BodyJson(obj).
		Do(ctx)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("success to es")
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
	addEs(topic, obj)
}
