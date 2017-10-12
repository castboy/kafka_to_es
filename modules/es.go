package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	elastic "gopkg.in/olivere/elastic.v5"
)

func parseAlert(msg []byte, alertType string) (interface{}, error) {
	switch alertType {
	case "ids":
		var alert IdsAlertObj
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
