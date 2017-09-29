package modules

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var dbHdl *sql.DB

func Mysql() {
	user, pwd, host, port, db := mysqlConf()
	database(user, pwd, host, port, db)
}

func mysqlConf() (user, pwd, host, port, db string) {
	host = conf.GetValue("mysql", "host")
	port = conf.GetValue("mysql", "port")
	user = conf.GetValue("mysql", "user")
	pwd = conf.GetValue("mysql", "passwd")
	db = conf.GetValue("mysql", "db")

	return user, pwd, host, port, db
}

func database(usr, pwd, host, port, db string) {
	var err error

	connParams := usr + ":" + pwd + "@tcp(" + host + ":" + port + ")/" + db
	dbHdl, err = sql.Open("mysql", connParams)
	if err != nil {
		log.Fatal(err)
	}

	err = dbHdl.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func vdsAlertSql(alert VdsAlert) string {
	sql := fmt.Sprintf(`insert into %s (log_time, threatname, subfile, 
		local_threatname, local_vtype, local_platfrom, local_vname, 
		local_extent, local_enginetype,local_logtype, local_engineip, 
		sourceip, destip, sourceport, destport, app_file,http_url) values (
		%d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %d,%s, %s)`,
		"alert_vds", "", alert.Threatname, "", alert.Local_threatname,
		alert.Local_vtype, alert.Local_platfrom, alert.Local_vname,
		alert.Local_extent, alert.Local_enginetype, alert.Local_logtype,
		alert.Local_engineip, "", "", "", "", "", "", "")

	return sql
}

func vdsAlert(sql string) {
	stmt, err := dbHdl.Prepare(sql)
	if err != nil {
		log.Fatal(err)
	}

	defer stmt.Close()

	_, err = stmt.Exec()
	if err != nil {
		log.Fatal(err)
	}
}
