package modules

import (
	"encoding/base64"
	"os"
	"time"

	"github.com/colinmarc/hdfs"
)

var HdfsClients = make(map[string][]*hdfs.Client)

func InitHdfsClis() {
	for t, v := range consumers[0] {
		for p, _ := range v {
			InitHdfsCli(t, int32(p), nameNode)
		}
	}
}

func InitHdfsCli(topic string, partition int32, namenode string) {
	client, err := hdfs.New(namenode + ":8020")
	if nil != err {
		Log("CRT", "Init Hdfs Client Err, %s", err.Error())
	}

	if _, ok := HdfsClients[topic]; !ok {
		HdfsClients[topic] = make([]*hdfs.Client, 0)
	}

	HdfsClients[topic] = append(HdfsClients[topic], client)
}

func ReHdfsCli(topic string, partition int32) {
	HdfsClients[topic][partition].Close()
	InitHdfsCli(topic, partition, nameNode)
	Log("INF", "ReHdfsCli, %s", time.Now())
}

func hdfsRd(topic string, partition int32, file string, offset int64, size int) (s string) {
	var f *hdfs.FileReader
	var err error

	defer func() {
		if r := recover(); r != nil {
			Log("ERR", "hdfsRd panic recover")
		}
	}()

	f, err = HdfsClients[topic][partition].Open(file)
	if nil != err {
		if _, ok := err.(*os.PathError); ok {
			Log("ERR", "Open Hdfs File %s Path Err", file)
		} else {
			ReHdfsCli(topic, partition)
			for {
				f, err = HdfsClients[topic][partition].Open(file)
				if nil == err {
					break
				}
			}
		}
	}

	bytes := make([]byte, size)
	_, err = f.ReadAt(bytes, offset)

	f.Close()

	if nil != err {
		Log("ERR", "Read Hdfs, file = %s, offset = %d, size = %d fileSize = %d", file, offset, size, f.Stat().Size())
	}

	s = base64.StdEncoding.EncodeToString(bytes)

	return s
}
