package modules

import (
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
	for {
		bytes, err := consume(consumers[topic][partition])
		if nil != err {
			time.Sleep(60 * time.Second)
			Log("WRN", "no data in %s %d partiton", topic, partition)
		} else {
			alert, xdr, err := parseXdrAlert(bytes, alertType)
			if nil == err {
				toEs(bytes, alert, xdr, topic)
				//			toMysql(alert, xdr, topic, alertType)
				sendStatusMsg(topic, partition)
			}
		}
	}
}

func sendStatusMsg(topic string, partition int32) {
	statusCh <- statusMsg{topic, partition}
}
