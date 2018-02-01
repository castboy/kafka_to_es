package modules

import (
	"regexp"
	"strconv"
	"sync"
	"time"
)

var Wg sync.WaitGroup

func Parallel() {
	for db, _ := range consumers {
		for t, v := range topic {
			for p, _ := range v {
				go toDb(db, t, int32(p), alertType(t))
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

func toDb(db int, topic string, partition int32, alertType string) {
	for {
		bytes, err := consume(consumers[db][topic][partition])
		if nil != err {
			time.Sleep(60 * time.Second)
			Log("WRN", "no data in [topic partition] %s", topic, strconv.Itoa(int(partition)))
		} else {
			alert, xdr, err := parseXdrAlert(bytes, alertType)
			if nil == err {
				if ES == db {
					toEs(bytes, alert, xdr, topic, partition)
					sendStatusMsg(db, topic, partition)
				} else if MYSQL == db {
					toMysql(alert, xdr, topic, alertType)
					sendStatusMsg(db, topic, partition)
				}

			}
		}
	}
}

func sendStatusMsg(db int, topic string, partition int32) {
	statusCh <- statusMsg{Db: db, K: KafkaInfo{Topic: topic, Partition: partition}}
}
