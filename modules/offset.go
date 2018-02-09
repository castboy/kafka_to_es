package modules

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func ResetOffsetInConfFile() {
	conf := "conf/conf.ini"

	line := fmt.Sprintf("sed -n '/offset/=' %s", conf)
	out, err := exec.Command("sh", "-c", line).Output()
	s := strings.Replace(string(out), "\n", "", -1)
	i, err := strconv.Atoi(s)

	vds := i + 1
	waf := i + 2
	ids := i + 3

	r := fmt.Sprintf("sed -i '%dc vds = -1' %s", vds, conf)
	out, err = exec.Command("sh", "-c", r).Output()
	if nil != err {
		Log("WRN", "reset vds = -1 err, %s", err.Error())
	} else {
		Log("INF", "reset vds = -1 ok")
	}

	r = fmt.Sprintf("sed -i '%dc waf = -1' %s", waf, conf)
	out, err = exec.Command("sh", "-c", r).Output()
	if nil != err {
		Log("WRN", "reset waf = -1 err, %s", err.Error())
	} else {
		Log("INF", "reset waf = -1 ok")
	}

	r = fmt.Sprintf("sed -i '%dc ids = -1' %s", ids, conf)
	out, err = exec.Command("sh", "-c", r).Output()
	if nil != err {
		Log("WRN", "reset ids = -1 err, %s", err.Error())
	} else {
		Log("INF", "reset ids = -1 ok")
	}
}
