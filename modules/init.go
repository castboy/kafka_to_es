package modules

import (
	"encoding/json"
	"strings"

	"github.com/widuu/goini"
)

var topic = make(map[string][]string)
var status = make(map[string][]int64)
var conf *goini.Config
var esNodes string
var esIndex string
var port string
var nameNode string

func init() {
	getConf()
	initCli()
	initBroker()
	InitLog()
	InitEtcdCli()
	initStatus()
}

func getConf() {
	conf = goini.SetConfig("conf/conf.ini")
	confList := conf.ReadList()
	esNodes = conf.GetValue("elasticsearch", "nodes")
	port = conf.GetValue("elasticsearch", "port")
	esIndex = conf.GetValue("elasticsearch", "index")
	nameNode = conf.GetValue("hdfs", "nameNode")

	parsePartition(confList[0]["topic"])
}

func parsePartition(topics map[string]string) {
	for k, v := range topics {
		topic[k] = strings.Split(v, ",")
	}
}

func initStatus() {
	for t, _ := range topic {
		status[t] = make([]int64, 0)
	}

	if getStatus() {

	} else {
		firstRunStatus()
	}

	bytes, err := json.Marshal(status)
	if nil != err {
		Log("ERR", "%s", "json.Marshal status err")
	}

	Log("INF", "init status: %s", string(bytes))
}

func firstRunStatus() {
	for t, v := range topic {
		for k, _ := range v {
			start, _ := offset(t, int32(k))
			status[t] = append(status[t], start)
		}
	}

}

func getStatus() bool {
	b, ok := EtcdGet("apt/kafka_to_db/status")
	if ok {
		err = json.Unmarshal(b, &status)
		if nil != err {
			return false
		}
	} else {
		Log("ERR", "%s", "getStatusFromEtcd")
		return false
	}

	return true
}
