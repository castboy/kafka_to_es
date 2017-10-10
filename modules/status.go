package modules

import (
	"encoding/json"
	//	"fmt"
	"io/ioutil"
	"log"
	"time"
)

type statusMsg struct {
	Topic     string
	Partition int32
}

var statusCh = make(chan statusMsg, 100)
var recordCh = make(chan bool)

func RecordStatus() {
	for {
		select {
		case msg := <-statusCh:
			status[msg.Topic][msg.Partition]++
		case <-recordCh:
			record()
		}
	}
}

func SendRecordStatusMsg(seconds int) {
	ticker := time.NewTicker(time.Second * time.Duration(seconds))
	for _ = range ticker.C {
		recordCh <- true
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
