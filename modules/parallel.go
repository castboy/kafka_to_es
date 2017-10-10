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
		switch alertType(t) {
		case "vds":
			for p, _ := range v {
				go vdsToDb(t, int32(p))
				Wg.Add(1)
			}
		case "waf":
			for p, _ := range v {
				go wafToDb(t, int32(p))
				Wg.Add(1)
			}
		case "ids":
			for p, _ := range v {
				go idsToDb(t, int32(p))
				Wg.Add(1)
			}
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

func vdsToDb(topic string, partition int32) {
	for {
		bytes := consume(consumers[topic][partition])
		fmt.Println(string(bytes))
		alert, alertErr := parseVdsAlert(bytes)
		xdr, xdrErr := parseXdr(bytes)
		if nil == alertErr && nil == xdrErr {
			toEs(bytes, alert, xdr, topic)
			vdsToMysql(alert, topic, xdr)
			statusCh <- statusMsg{topic, partition}
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}

func wafToDb(topic string, partition int32) {
	for {
		bytes := consume(consumers[topic][partition])
		fmt.Println(string(bytes))
		alert, alertErr := parseWafAlert(bytes)
		xdr, xdrErr := parseXdr(bytes)
		if nil == alertErr && nil == xdrErr {
			toEs(bytes, alert, xdr, topic)
			wafToMysql(alert, topic, xdr)
			statusCh <- statusMsg{topic, partition}
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}

func idsToDb(topic string, partition int32) {
	for {
		bytes := consume(consumers[topic][partition])
		fmt.Println(string(bytes))
		alert, alertErr := parseIdsAlert(bytes)
		xdr, xdrErr := parseXdr(bytes)
		if nil == alertErr && nil == xdrErr {
			toEs(bytes, alert, xdr, topic)
			idsToMysql(alert)
			statusCh <- statusMsg{topic, partition}
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}
