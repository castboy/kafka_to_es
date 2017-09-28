package modules

import (
	"encoding/json"
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
