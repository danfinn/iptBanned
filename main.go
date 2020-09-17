package main

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sort"
	"flag"
)

var f2bRules []string
var chain string

func getBanned(ipt *iptables.IPTables) []string {
	f2bRules, err := ipt.List("filter", chain)
	if err != nil {
		fmt.Printf("List of %v chain failed failed: %v", chain, err)
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
        ipt, err := iptables.New()
        if err != nil {
                log.Fatal("Unable to connect to iptables")
        }

        f2bRules = getBanned(ipt)

	tpl, err := template.ParseFiles("/usr/local/iptBanned/banned.gohtml")
	if err != nil {
		log.Fatalln(err)
	}

	err = tpl.Execute(res, f2bRules)
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	// Handle CLI arguments
	var port string
	flag.StringVar(&port, "p", "8080", "Port to listen on")
	flag.StringVar(&chain, "c", "f2b-SSH", "IPTables Chain to display")
	flag.Parse()

	http.HandleFunc("/", showBanned)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/usr/local/iptBanned/static"))))
	http.ListenAndServe(":"+port, nil)
}
