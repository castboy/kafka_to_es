package modules

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/widuu/goini"
)

var topic = make(map[string][]string)
var offsetReset = make(map[string][]string)
var status = make([]map[string][]int64, 2)
var (
	ES    = 0
	MYSQL = 1
)

var conf *goini.Config
var esNodes string
var esIndex string
var bulkBlock int
var port string
var nameNode string
var intoMysql bool

func init() {
	getConf()
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
	bulkBlock, err = strconv.Atoi(conf.GetValue("elasticsearch", "bulkBlock"))
	if nil != err {
		bulkBlock = 200
	}
	nameNode = conf.GetValue("hdfs", "nameNode")
	intoMysql, _ = strconv.ParseBool(conf.GetValue("insertDb", "mysql"))

	parsePartition(confList[0]["topic"])
	parseOffset(confList[1]["offset"])

}

func parsePartition(topics map[string]string) {
	for k, v := range topics {
		topic[k] = strings.Split(v, ",")
	}
}

func parseOffset(topics map[string]string) {
	for k, v := range topics {
		offsetReset[k] = strings.Split(v, ",")
	}
}

func initStatus() {
	for db, _ := range status {
		status[db] = make(map[string][]int64)
		for t, _ := range topic {
			status[db][t] = make([]int64, 0)
		}
	}

	if getStatus() {
		statusCheck()
	} else {
		firstRunStatus()
	}

	bytes, err := json.Marshal(status)
	if nil != err {
		Log("ERR", "%s", "json.Marshal statusEs err")
	}

	Log("INF", "init status: %s", string(bytes))
}

func firstRunStatus() {
	for db, _ := range status {
		for t, v := range topic {
			for k, _ := range v {
				start, _ := Offset(t, int32(k))
				status[db][t] = append(status[db][t], start)
			}
		}
	}
}

func getStatus() bool {
	b, ok := EtcdGet("apt/kafka_to_db/status")
	if ok {
		err = json.Unmarshal(b, &status)
		if nil != err {
			Log("ERR", "%s", "json.Unmarshal(b, &status)")
			return false
		}
	} else {
		Log("ERR", "%s", "getStatusFromEtcd")
		return false
	}

	return true
}

func statusCheck() {
	for db, topics := range status {
		for t, v := range topics {
			for p, o := range v {
				statusCorrect(db, t, int32(p), o)
			}
		}
	}
}

func statusCorrect(db int, topic string, partition int32, offset int64) {
	start, end := Offset(topic, partition)
	if offset < start || offset > end {
		status[db][topic][partition] = start
		Log("WRN", "%s is reset to start offset", topic)
	}

	oft, err := strconv.Atoi(offsetReset[topic][partition])
	if nil == err && -1 != oft && start < int64(oft) && int64(oft) < end {
		status[db][topic][partition] = int64(oft)
		Log("INF", "%s is reset to conf offset", topic)
	}
}
