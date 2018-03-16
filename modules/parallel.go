package modules

import (
	"encoding/json"
	"regexp"
	"sync"
)

var Wg sync.WaitGroup

func Parallel() {
	for db, _ := range consumers {
		for t, v := range topic {
			for p, _ := range v {
				if MYSQL == db && !intoMysql {
				} else {
					go toDb(db, t, int32(p), alertType(t))
					Wg.Add(1)
				}
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

func prepareBulkEsObj(db int, topic string, partition int32, alertType string) ([]string, int) {
	var objBucket = make([]string, 0)
	var num int

	for i := 0; i < bulkBlock; i++ {
		bytes, err := consume(consumers[db][topic][partition])
		if nil != err {
			break
		} else {
			num++
			alert, xdr, err := parseXdrAlert(bytes, alertType)
			if err == nil {
				obj := esObj(alert, xdr, topic, partition)
				byte, err := json.Marshal(obj)
				if nil != err {
					Log("ERR", "json.Marshal(esObj): %s", err)
				} else {
					objBucket = append(objBucket, string(byte))
				}
			} else {
				Log("ERR", "parseXdrAlert: %s", err)
			}
		}
	}

	return objBucket, num
}

func esBulkIndexHeader(topic string) string {
	return `{ "index" : { "_index" : "test", "_type" : "` + esType(topic) + `"}}`
}

func bulkIndexItem(header, body string) string {
	return header + "\n" + body + "\n"
}

func bulkIndexContent(objBucket []string, topic string) (data string) {
	header := esBulkIndexHeader(topic)
	for _, body := range objBucket {
		data += bulkIndexItem(header, body)
	}

	return
}

func toDb(db int, topic string, partition int32, alertType string) {
	for {
		objBucket, num := prepareBulkEsObj(db, topic, partition, alertType)
		if 0 != len(objBucket) {
			cont := bulkIndexContent(objBucket, topic)
			toEs(cont, topic)
		}

		if 0 != num {
			sendStatusMsg(db, topic, partition, int64(num))
		}
	}
}

func sendStatusMsg(db int, topic string, partition int32, num int64) {
	statusCh <- statusMsg{Db: db, K: KafkaInfo{Topic: topic, Partition: partition}, N: num}
}
