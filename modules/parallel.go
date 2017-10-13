package modules

import (
	"fmt"
	"regexp"
	"sync"
	"time"
)

var Wg sync.WaitGroup

func Parallel() {
	for t, v := range consumers {
		for p, _ := range v {
			go toDb(t, int32(p), alertType(t))
			Wg.Add(1)
		}
	}
}

func alertType(topic string) string {
	if match, _ := regexp.MatchString("ids.*", topic); match {
		return "ids"
	}
	if match, _ := regexp.MatchString("vds.*", topic); match {
		return "vds"
	}
	if match, _ := regexp.MatchString("waf.*", topic); match {
		return "waf"
	}

	return ""
}

func toDb(topic string, partition int32, alertType string) {
	fmt.Println("alertType:_____________", alertType)
	for {
		bytes := consume(consumers[topic][partition])
		fmt.Println(string(bytes))
		alert, xdr, err := parseXdrAlert(bytes, alertType)
		if nil == err {
			toEs(bytes, alert, xdr, topic)
			toMysql(alert, xdr, topic, alertType)
			sendStatusMsg(topic, partition)
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}

func sendStatusMsg(topic string, partition int32) {
	statusCh <- statusMsg{topic, partition}
}
