package main

import (
	//	"fmt"

	"./modules"
	_ "./modules"
)

func main() {
	//	go RecordStatus()
	modules.Kafka()
}
