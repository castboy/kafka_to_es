package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	elastic "gopkg.in/olivere/elastic.v5"
)

func idsAlertObj(alert IdsAlert) IdsAlertTo {
	src_ip_info := SIpInfoTo{
		Country:         alert.Src_ip_info.Country,
		Province:        alert.Src_ip_info.Province,
		City:            alert.Src_ip_info.City,
		Organization:    alert.Src_ip_info.Organization,
		Network:         alert.Src_ip_info.Network,
		Lng:             alert.Src_ip_info.Lng,
		Lat:             alert.Src_ip_info.Lat,
		TimeZone:        alert.Src_ip_info.TimeZone,
		UTC:             alert.Src_ip_info.UTC,
		RegionalismCode: alert.Src_ip_info.RegionalismCode,
		PhoneCode:       alert.Src_ip_info.PhoneCode,
		CountryCode:     alert.Src_ip_info.CountryCode,
		ContinentCode:   alert.Src_ip_info.ContinentCode,
	}

	dest_ip_info := DIpInfoTo{
		Country:         alert.Dest_ip_info.Country,
		Province:        alert.Dest_ip_info.Province,
		City:            alert.Dest_ip_info.City,
		Organization:    alert.Dest_ip_info.Organization,
		Network:         alert.Dest_ip_info.Network,
		Lng:             alert.Dest_ip_info.Lng,
		Lat:             alert.Dest_ip_info.Lat,
		TimeZone:        alert.Dest_ip_info.TimeZone,
		UTC:             alert.Dest_ip_info.UTC,
		RegionalismCode: alert.Dest_ip_info.RegionalismCode,
		PhoneCode:       alert.Dest_ip_info.PhoneCode,
		CountryCode:     alert.Dest_ip_info.CountryCode,
		ContinentCode:   alert.Dest_ip_info.ContinentCode,
	}

	obj := IdsAlertTo{
		Time:         alert.Time,
		Src_ip:       alert.Src_ip,
		Src_ip_info:  src_ip_info,
		Src_port:     alert.Src_port,
		Dest_ip:      alert.Dest_ip,
		Dest_ip_info: dest_ip_info,
		Dest_port:    alert.Dest_port,
		Proto:        alert.Proto,
		Byzoro_type:  alert.Byzoro_type,
		Attack_type:  alert.Attack_type,
		Details:      alert.Details,
		Severity:     alert.Severity,
		Engine:       alert.Engine,
	}

	return obj
}

func parseAlert(msg []byte, alertType string) (interface{}, error) {
	switch alertType {
	case "ids":
		var alert IdsAlert
		err := json.Unmarshal(msg, &alert)
		alertObj := idsAlertObj(alert)
		return alertObj, err
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
		rt.Xdr = xdrSlice
		alert = rt
	case WafAlert:
		rt.Xdr = xdrSlice
		alert = rt
	case IdsAlert:
		alert = rt
	}

	return alert
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
