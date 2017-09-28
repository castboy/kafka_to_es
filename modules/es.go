package modules

import (
	"encoding/json"
	"fmt"
)

func esObj(msg []byte) VdsAlert {
	var obj VdsAlertObj
	err := json.Unmarshal(msg, &obj)
	if nil != err {
		fmt.Println("alert decode err")
	}

	var xdr BackendObj
	err = json.Unmarshal(msg, &xdr)
	if nil != err {
		fmt.Println("alert decode err")
	}

	var xdrSlice = make([]BackendObj, 0)
	xdrSlice = append(xdrSlice, xdr)

	obj.Alert.Xdr = xdrSlice

	return obj.Alert
}
