package main

import (
	//	"fmt"

	"./modules"
	//	_ "./modules"
)

func main() {
	go modules.SendRecordStatusMsg(5)
	go modules.RecordStatus()
	modules.Kafka()
	modules.Mysql()
	modules.Parallel()

	modules.Wg.Wait()
}
