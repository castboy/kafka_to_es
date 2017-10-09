package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/widuu/goini"
)

var topic = make(map[string][]string)
var status = make(map[string][]int64)
var conf *goini.Config

func init() {
	getConf()
	initStatus()
}

func getConf() {
	conf = goini.SetConfig("conf/conf.ini")
	confList := conf.ReadList()
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
		fmt.Println("status code err")
	}
	fmt.Println(string(bytes))
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
		log.Fatalln("fail to get run-status of exit last time")
	}

	defer fi.Close()

	fd, err := ioutil.ReadAll(fi)
	if nil != err {
		fmt.Println("log/status read err")
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
