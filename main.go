package main

import (
	//	"fmt"

	"kafka_to_es/modules"
	//	_ "./modules"
)

func main() {
	//	go modules.SendRecordStatusMsg(5)
	go modules.RecordStatus()
	modules.Kafka()

	modules.InitHdfsClis()

	modules.Mysql()
	modules.Parallel()

	modules.Wg.Wait()
}
