package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sort"
	"time"
	"os/exec"
)

var chain string

func getBanned(ipt *iptables.IPTables) ([]string, error) {
	var ips []string
	rules, err := ipt.List("filter", chain)
	if err != nil {
		fmt.Printf("List of %v chain failed failed: %v", chain, err)
		return ips, errors.New("getBanned unable to lookup iptables chain")
	}

	// Strip out IP addresses from iptables output
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	for _, v := range rules {
		rule := re.FindString(v)
		if rule != "" {
			ips = append(ips, rule)
		}
	}

	sort.Strings(ips)
	return ips, nil
}

func showBanned(res http.ResponseWriter, req *http.Request) {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatal("Unable to connect to iptables")
	}

	// Log some request info
	fmt.Printf("%v Req: %s %s\n", time.Now().Format(time.RFC3339), req.RemoteAddr, req.URL)

	f2bRules, err := getBanned(ipt)
	if err != nil {
		http.Error(res, "Unable to list IPTables chain", 500)
	} else {
		tpl, err := template.ParseFiles("/usr/local/iptBanned/banned.gohtml")
		if err != nil {
			http.Error(res, "Unable to parse html template", 500)
		}

		err = tpl.Execute(res, f2bRules)
		if err != nil {
			http.Error(res, "Unable to execute html template", 500)
		}
	}
}

func unbanIP (res http.ResponseWriter, req *http.Request) {
	tpl, err := template.ParseFiles("/usr/local/iptBanned/unban.gohtml")
	if err != nil {
		http.Error(res, "Unable to parse html template", 500)
	}

	if req.Method != http.MethodPost {
	  tpl.Execute(res, nil)
	  return
	}

	ipaddr := req.FormValue("ip")
	cmd := exec.Command("/usr/bin/fail2ban-client", "set", "sshd", "unbanip", ipaddr)
	err = cmd.Run()

	if err != nil {
		http.Error(res, "Unable to remove IP, please contact DevOps", 500)
	} else {
		tpl.Execute(res, struct{ Success bool }{ true })
	}

}

func main() {
	// Handle CLI arguments
	var port string
	flag.StringVar(&port, "p", "8080", "Port to listen on")
	flag.StringVar(&chain, "c", "f2b-SSH", "IPTables Chain to display")
	flag.Parse()

	fmt.Printf("iptBanned listening on port %v\n\n", port)

	http.HandleFunc("/", showBanned)
	http.HandleFunc("/unban", unbanIP)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/usr/local/iptBanned/static"))))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
