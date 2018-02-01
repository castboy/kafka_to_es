package modules

import (
	"encoding/json"
	//	"fmt"
	"time"
)

type statusMsg struct {
	Topic     string
	Partition int32
}

var statusCh = make(chan statusMsg, 100)
var recordCh = make(chan bool)

func RecordStatus() {
	ticker := time.NewTicker(time.Second * time.Duration(3))

	for {
		select {
		case msg := <-statusCh:
			status[msg.Topic][msg.Partition]++
		case <-ticker.C:
			record()
		}
	}
}

func record() {
	b, err := json.Marshal(status)
	if nil != err {
		Log("ERR", "%s", "json.Marshal(status)")
	} else {
		EtcdSet("apt/kafka_to_db/status", string(b))
	}
}
