package modules

import (
	"context"
	"encoding/json"

	elastic "gopkg.in/olivere/elastic.v5"
)

func parseVdsAlert(msg []byte) (VdsAlert, error) {
	var alert VdsAlertObj
	err := json.Unmarshal(msg, &alert)
	return alert.Alert, err
}

func parseIdsAlert(msg []byte) (IdsAlert, error) {
	var alert IdsAlert
	err := json.Unmarshal(msg, &alert)
	return alert, err
}

func parseWafAlert(msg []byte) (WafAlert, error) {
	var alert WafAlertObj
	err := json.Unmarshal(msg, &alert)
	return alert.Alert, err
}

func parseXdr(msg []byte) (BackendObj, error) {
	var xdr BackendObj
	err := json.Unmarshal(msg, &xdr)

	return xdr, err
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
	var esType string
	switch topic {
	case "waf-alert":
		esType = "waf_alert"
	case "vds-alert":
		esType = "vds_alert"
	case "ids-alert":
		esType = "ids_alert"
	}

	ctx := context.Background()
	client, err := elastic.NewClient(elastic.SetURL("http://10.88.1.102:9200"))
	if err != nil {
	}

	_, err = client.Index().
		Index("apt").
		Type(esType).
		BodyJson(obj).
		Do(ctx)
	if err != nil {
		panic(err)
	}
}

func toEs(msg []byte, alert interface{}, xdr BackendObj, topic string) {
	obj := esObj(msg, alert, xdr)
	addEs(topic, obj)
}
