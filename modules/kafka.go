package modules

import (
	"fmt"
	"log"

	"github.com/optiopay/kafka"
)

var broker kafka.Client
var consumers = make(map[string][]kafka.Consumer)

func initConsumer(topic string, partition int32, start int64) (kafka.Consumer, error) {
	conf := kafka.NewConsumerConf(topic, partition)
	conf.StartOffset = start
	conf.RetryLimit = 1
	consumer, err := broker.Consumer(conf)

	if err != nil {
		errLog := fmt.Sprintf("cannot initConsumer of %s %d partition", topic, partition)
		Log("Err", errLog)
	}

	return consumer, err
}

func initBroker(localhost string) {
	var kafkaAddrs []string = []string{localhost + ":9092", localhost + ":9093"}
	conf := kafka.NewBrokerConf("agent")
	conf.AllowTopicCreation = false

	var err error
	broker, err = kafka.Dial(kafkaAddrs, conf)
	if err != nil {
		Log("Err", "cannot connect to kafka cluster")
		log.Fatalf("cannot connect to kafka cluster: %s", err)
	}

	defer broker.Close()
}

func initConsumers(partition int32) {
	for t, v := range topic {
		for p, _ := range v {
			consumers[t][p] = initConsumer(t, p)
		}
	}
}
