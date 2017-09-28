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

func toEs(obj VdsAlert) {
	ctx := context.Background()
	client, err := elastic.NewClient(elastic.SetURL("http://10.88.1.102:9200"))
	if err != nil {
	}

	_, err = client.Index().
		Index("apt").
		Type("vds_alert").
		BodyJson(obj).
		Do(ctx)
	if err != nil {
		panic(err)
	}
}
