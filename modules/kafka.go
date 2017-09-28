package modules

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

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
		log.Fatalln(errLog)
	}

	return consumer, err
}

func initBroker(localhost string) {
	var kafkaAddrs []string = []string{localhost + ":9092", localhost + ":9093"}
	conf := kafka.NewBrokerConf("kafka_to_es")
	conf.AllowTopicCreation = false

	var err error
	broker, err = kafka.Dial(kafkaAddrs, conf)
	if err != nil {
		log.Fatalf("cannot connect to kafka cluster: %s", err)
	}

	defer broker.Close()
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

func consume(consumer kafka.Consumer) {
	for {
		msg, err := consumer.Consume()
		if nil != err {
			time.Sleep(5 * time.Second)
			fmt.Println("no data in topic")
		} else {
			var obj VdsAlertObj
			err := json.Unmarshal(msg.Value, &obj)
			if nil != err {
				fmt.Println("alert decode err")
			}
			fmt.Println(obj.Alert)

			var backendobj BackendObj
			err = json.Unmarshal(msg.Value, &backendobj)
			if nil != err {
				fmt.Println("alert decode err")
			}
                        
                        var xdrSlice = make([]BackendObj, 0)
                        xdrSlice = append(xdrSlice, backendobj)

                        obj.Alert.Xdr = xdrSlice
                        
			fmt.Println(obj.Alert)
		}
	}

}

func Kafka() {
	host := conf.GetValue("kafka", "host")
	initBroker(host)
	initConsumers()
	consume(consumers["vds-alert"][0])
}
