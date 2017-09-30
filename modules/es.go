package modules

import (
	"context"
	"encoding/json"

	elastic "gopkg.in/olivere/elastic.v5"
)

func parseAlert(msg []byte) (VdsAlert, error) {
	var alert VdsAlertObj
	err := json.Unmarshal(msg, &alert)
	return alert.Alert, err
}

func parseXdr(msg []byte) (BackendObj, error) {
	var xdr BackendObj
	err := json.Unmarshal(msg, &xdr)

	return xdr, err
}

func esObj(msg []byte, alert VdsAlert, xdr BackendObj) VdsAlert {
	var xdrSlice = make([]BackendObj, 0)
	xdrSlice = append(xdrSlice, xdr)

	alert.Xdr = xdrSlice

	return alert
}

func toEs(topic string, obj VdsAlert) {
	var esType string
	switch topic {
	case "waf-alert":
		esType = "waf_alert"
	case "vds-alert":
		esType = "vds_alert"
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
