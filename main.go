package main

import (
	//	"fmt"

	"kafka_to_es/modules"
	//	_ "./modules"
)

func main() {
	go modules.RecordStatus()
	modules.Kafka()

	modules.InitHdfsClis()

	modules.Mysql()
	modules.Parallel()

	modules.ResetOffsetInConfFile()

	modules.Wg.Wait()
}
