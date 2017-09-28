package modules

import (
	"fmt"
	"sync"
	"time"
)

var Wg sync.WaitGroup

func Parallel() {
	for t, v := range consumers {
		for p, _ := range v {
			go kafkaToEs(t, p)
			Wg.Add(1)
		}
	}
}

func kafkaToEs(topic string, partition int) {
	for {
		bytes := consume(consumers[topic][partition])
		alert, alertErr := parseAlert(bytes)
		xdr, xdrErr := parseXdr(bytes)
		if nil == alertErr && nil == xdrErr {
			obj := esObj(bytes, alert, xdr)
			fmt.Println(obj)
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}
