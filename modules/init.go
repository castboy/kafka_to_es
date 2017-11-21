package modules

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	"github.com/widuu/goini"
)

var topic = make(map[string][]string)
var status = make(map[string][]int64)
var conf *goini.Config
var esNode string
var port string
var exit = "Shut down due to critical fault."

func init() {
	getConf()
	initStatus()
}

func getConf() {
	conf = goini.SetConfig("conf/conf.ini")
	confList := conf.ReadList()
	esNode = conf.GetValue("elasticsearch", "host")
	port = conf.GetValue("elasticsearch", "port")

	initCli()
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

	confStatus()

	bytes, err := json.Marshal(status)
	if nil != err {
		Log("ERR", "%s", "json.Marshal status err")
	}

	Log("INF", "init status: %s", string(bytes))
}

func firstRunStatus() {
	for t, v := range topic {
		for range v {
			status[t] = append(status[t], -2)
		}
	}

}
func getStatus() bool {
	fi, err := os.Open("log/status")
	if err != nil {
		Log("ERR", "%s", "open log/status err")
	}

	defer fi.Close()

	fd, err := ioutil.ReadAll(fi)
	if nil != err {
		Log("ERR", "%s", "read log/status err")
	}

	err = json.Unmarshal(fd, &status)
	if nil != err {
		return false
	}

	return true
}

func confStatus() {
	start := conf.GetValue("kafka", "start")
	switch start {
	case "first":
		putStatus(-2)
	case "last":
		putStatus(-1)
	default:
	}
}

func putStatus(s int64) {
	for t, v := range status {
		for p, _ := range v {
			status[t][p] = s
		}
	}
}
