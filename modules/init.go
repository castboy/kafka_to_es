package modules

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/widuu/goini"
)

var topic = make(map[string][]string)

func init() {
	fmt.Println("init")
	getConf()

}

func getConf() {
	conf := goini.SetConfig("conf/conf.ini")
	confList := conf.ReadList()
	parsePartition(confList[0]["topic"])
}

func parsePartition(topics map[string]string) {
	for k, v := range topics {
		topic[k] = strings.Split(v, ",")
	}
	fmt.Println(Topic)
}

func getStatus() {
	fi, err := os.Open("log/status")
	if err != nil {
		log.Fatalln("fail to get run-status of exit last time")
	}

	defer fi.Close()

	fd, err := ioutil.ReadAll(fi)
	json.Unmarshal(fd, &status)
}
