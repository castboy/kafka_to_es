package modules

import (
	"fmt"
	"log"
	"strconv"
	"strings"

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
		errLog := fmt.Sprintf("can not init consumer of [topic partition] %s", topic, strconv.Itoa(int(partition)))
		Log("CRT", "%s", errLog)
	}

	Log("INF", "init consumer ok: ", topic, int(partition))

	return consumer, err
}

func initBroker() {
	brokers := conf.GetValue("kafka", "brokers")
	addrs := brokerAddrs(brokers)
	conf := kafka.NewBrokerConf("kafka_to_es")
	conf.AllowTopicCreation = false

	var err error
	broker, err = kafka.Dial(addrs, conf)
	if err != nil {
		Log("CRT", "cannot connect to kafka cluster: %s", addrs)
		log.Fatal(exit)
	}
}

func initConsumers() {
	for k, _ := range consumers {
		consumers[k] = make([]kafka.Consumer, 0)
	}

	for t, v := range status {
		for p, s := range v {
			c, _ := initConsumer(t, int32(p), s)
			consumers[t] = append(consumers[t], c)
		}
	}
}

func consume(consumer kafka.Consumer) ([]byte, error) {
	var bytes []byte
	msg, err := consumer.Consume()
	if nil != err {
		return bytes, err
	}

	return msg.Value, nil
}

func brokerAddrs(brokers string) []string {
	s := make([]string, 0)
	for _, v := range strings.Split(brokers, ",") {
		s = append(s, v+":9092")
	}

	return s
}

func offset(topic string, partition int32) (int64, int64) {
	start, _ := broker.OffsetEarliest(topic, partition)
	end, _ := broker.OffsetLatest(topic, partition)

	return start, end
}

func Kafka() {
	initConsumers()
}
