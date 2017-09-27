package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
)

type statusMsg struct {
	Topic     string
	Partition int32
	Offset    int64
}

var status = make(map[string][]int64)
var statusCh = make(chan statusMsg, 100)

func recordStatus() {
	for {
		msg := <-statusCh
		status[mgs.Topic][msg.Partition] = msg.Offset
		record()
	}
}

func record() {
	byte, err := json.Marshal(status)
	if nil != err {
		log.Println("json.Marshal err in record()")
	}
	err = ioutil.WriteFile("log/status", byte, 0666)
	if nil != err {
		log.Println("ioutil.WriteFile err in record()")
	}
}
