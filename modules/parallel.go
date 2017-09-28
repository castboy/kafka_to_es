package modules

import (
	"fmt"
	"sync"
)

var Wg sync.WaitGroup

func Parallel() {
	for t, v := range consumers {
		for p, _ := range v {
			go kafkaToEs(t, p)
			Wg.Add(1)
		}
	}
}

func kafkaToEs(topic string, partition int) {
	for {
		bytes := consume(consumers[topic][partition])
		obj := esObj(bytes)
		fmt.Println(obj)
	}
}
