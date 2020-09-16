package main

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sort"
)

var f2bRules []string

func getBanned(ipt *iptables.IPTables) []string {
	f2bRules, err := ipt.List("filter", "f2b-SSH")
	if err != nil {
		fmt.Printf("List of f2b-SSH chain failed failed: %v", err)
	}

	// Strip out IP addresses from iptables output
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	var ips []string
	for _, v := range f2bRules {
		f2bRulesIPs := re.FindString(v)
		if f2bRulesIPs != "" {
			ips = append(ips, f2bRulesIPs)
		}
	}

	sort.Strings(ips)
	return ips
}

func showBanned(res http.ResponseWriter, req *http.Request) {
	tpl, err := template.ParseFiles("banned.gohtml")
	if err != nil {
		log.Fatalln(err)
	}

	err = tpl.Execute(res, f2bRules)
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatal("Unable to connect to iptables")
	}

	f2bRules = getBanned(ipt)

	http.HandleFunc("/", showBanned)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(":8080", nil)
}
