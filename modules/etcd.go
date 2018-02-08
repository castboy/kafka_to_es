package modules

import (
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/widuu/goini"
	"golang.org/x/net/context"
)

var EtcdCli *clientv3.Client

var EtcdNodes = make(map[string]string)

func InitEtcdCli() {
	conf := goini.SetConfig("conf/conf.ini")
	confList := conf.ReadList()
	EtcdNodes = confList[2]["etcd"]

	Log("INF", "%s", "InitEtcdCli")

	nodes := make([]string, 0)
	for _, val := range EtcdNodes {
		elmt := val + ":2379"
		nodes = append(nodes, elmt)
	}

	cfg := clientv3.Config{
		Endpoints:   nodes,
		DialTimeout: 5 * time.Second,
	}

	EtcdCli, err = clientv3.New(cfg)
	if err != nil {
		Log("CRT", "Init Etcd Client failed: %s", err.Error())
	}

	Log("INF", "%s", "Init Etcd Client Ok")
}

func EtcdSet(k, v string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	_, err := EtcdCli.Put(ctx, k, v)
	cancel()
	if err != nil {
		Log("ERR", "set etcd key err, k = %s, v = %s", k, v)
	}
}

func EtcdGet(key string) (bytes []byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			Log("ERR", "%s PANIC", "EtcdGet")
			bytes = []byte{}
			ok = false
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	resp, _ := EtcdCli.Get(ctx, key)
	cancel()

	return resp.Kvs[0].Value, true
}
