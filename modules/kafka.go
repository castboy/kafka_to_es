package modules

import (
	"fmt"
	"strconv"
	"strings"

	"time"

	"github.com/optiopay/kafka"
)

var broker kafka.Client
var consumers = make([]map[string][]kafka.Consumer, 2)

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
	}
}

func initConsumers() {
	for db, v := range consumers {
		consumers[db] = make(map[string][]kafka.Consumer)
		for t, _ := range v {
			consumers[db][t] = make([]kafka.Consumer, 0)
		}
	}

	for db, topics := range status {
		for t, v := range topics {
			for p, s := range v {
				c, _ := initConsumer(t, int32(p), int64(s))
				consumers[db][t] = append(consumers[db][t], c)
			}
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

func Offset(topic string, partition int32) (start, end int64) {
	for {
		start, err = broker.OffsetEarliest(topic, partition)
		if nil != err {
			Log("ERR", "get start offset err, %s", topic, partition)
		} else {
			time.Sleep(time.Duration(500) * time.Millisecond)
		}
	}
	for {
		end, err = broker.OffsetLatest(topic, partition)
		if nil != err {
			Log("ERR", "get end offset err, %s", topic, partition)
		} else {
			time.Sleep(time.Duration(500) * time.Millisecond)
		}
	}

	return start, end
}

func Kafka() {
	initConsumers()
}
