package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	ldap "gopkg.in/ldap.v2"
)

func main() {

	demoMode("", "", "", "", "", false, false)
	fmt.Println("all done")

}

const DC_SEPERATOR = ",dc="

type LdapDemo struct {
	conn                 *ldap.Conn
	gcConn               *ldap.Conn
	domain               string
	port                 int64
	useSSL               bool
	verifySSLCert        bool
	searchBase           string
	binduser             string
	bindpassword         string
	rootNamingContext    string
	defaultNamingContext string
}

func NewLdapDemo(domain string, port int64, username string, password string, useSSL bool, verifySSLCert bool) *LdapDemo {
	domainParts := strings.Split(domain, ".")
	searchBase := fmt.Sprintf("dc=%s", strings.Join(domainParts, DC_SEPERATOR))
	return &LdapDemo{
		domain:        domain,
		port:          port,
		useSSL:        useSSL,
		verifySSLCert: verifySSLCert,
		searchBase:    searchBase,
		binduser:      username,
		bindpassword:  password,
	}
}

func (demo *LdapDemo) ConnectToAD() error {
	err := demo.ConnectToGC()
	if err != nil {
		fmt.Println("error 1")
		// return err
	}

	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", demo.domain, demo.port))
	if err != nil {
		return err
	}
	demo.conn = l
	demo.bindAsReadOnlyUser(false)
	return nil
}

func (demo *LdapDemo) ConnectToGC() error {
	log.Print("connecting to GC")
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", demo.domain, 3268))
	if err != nil {
		return err
	}
	demo.gcConn = l

	demo.bindAsReadOnlyUser(true)

	search := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=domain)", nil, nil)
	response, err := l.Search(search)
	if err != nil {
		fmt.Println(err)
	}
	//response.PrettyPrint(1)
	demo.rootNamingContext = response.Entries[0].GetAttributeValue("rootDomainNamingContext")
	demo.defaultNamingContext = response.Entries[0].GetAttributeValue("defaultNamingContext")
	return nil
}

func (demo *LdapDemo) Disconnect() {
	if demo.conn != nil {
		demo.conn.Close()
	}
	if demo.gcConn != nil {
		demo.gcConn.Close()
	}
}

func (demo *LdapDemo) getDomainList() ([]*ldap.Entry, error) {
	domainAttributes := []string{"dnsRoot", "objectGUID", "nCName"}
	search := ldap.NewSearchRequest(fmt.Sprintf("CN=Partitions,CN=Configuration,%s", demo.rootNamingContext), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(netbiosname=*)", domainAttributes, nil)
	response, err := demo.conn.Search(search)
	if err != nil {
		fmt.Printf("%#v", err)
		return nil, err
	}
	return response.Entries, nil
}

func (demo *LdapDemo) searchForUsers(searchPath string, searchTerm string) ([]*ldap.Entry, error) {
	formattedSearchQuery := fmt.Sprintf("(&(objectCategory=user)(|(sn=%s)(name=%s)(displayName=%s)(sAMAccountName=%s)(userPrincipalName=%s)))", searchTerm, searchTerm, searchTerm, searchTerm, searchTerm)

	var searchResults *ldap.SearchResult
	var err error
	log.Printf("the search path is %s", searchPath)
	// if searchPath != demo.defaultNamingContext {
	// log.Println("connecting to GC")
	search := ldap.NewSearchRequest(searchPath, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, formattedSearchQuery, []string{"cn", "givenName", "sn", "mail", "dn", "sAMAccountName", "userPrincipalName", "userAccountControl", "memberOf", "objectGUID"}, nil)
	searchResults, err = demo.gcConn.Search(search)
	// } else {
	// search := ldap.NewSearchRequest(searchPath, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, formattedSearchQuery, []string{"cn", "givenName", "sn", "mail", "dn", "sAMAccountName", "userPrincipalName", "userAccountControl", "memberOf", "objectGUID"}, nil)
	// searchResults, err = demo.conn.Search(search)
	// }

	if err != nil {
		fmt.Print(err)
		return nil, err
	}

	for _, entry := range searchResults.Entries {
		entry.PrettyPrint(2)
		fmt.Println("--------------------------------------")
	}
	return searchResults.Entries, nil
}

func (demo *LdapDemo) getUsersGroups(entry *ldap.Entry) error {
	return nil
}

func (demo *LdapDemo) searchForGroups(searchPath string, searchTerm string) ([]*ldap.Entry, error) {
	formattedSearchQuery := fmt.Sprintf("(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(|(cn=%[1]s)(name=%[1]s)(sAMAccountName=%[1]s)))", searchTerm)

	foo := ldap.NewControlPaging(10)

	search := ldap.NewSearchRequest(searchPath, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, formattedSearchQuery, []string{"cn", "dn", "objectGUID"}, []ldap.Control{foo})

	searchResults, err := demo.gcConn.Search(search)

	if err != nil {
		return nil, err
	}
	pagingControl := ldap.FindControl(searchResults.Controls, ldap.ControlTypePaging)
	cookie := pagingControl.(*ldap.ControlPaging).Cookie
	if len(cookie) != 0 {
		cookieStr := base64.StdEncoding.EncodeToString(cookie)
		fmt.Printf("%#v", cookieStr)
	}
	// for _, entry := range searchResults.Entries {
	// 	// entry.PrettyPrint(2)
	// 	// fmt.Println("--------------------------------------")
	// }
	return searchResults.Entries, nil
}

func (demo *LdapDemo) authenticateUser(searchBase, username, password string) error {
	if searchBase == "" {
		searchBase = demo.searchBase
	}
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(sAMAccountName=%s)", username), []string{"dn"}, nil)

	sr, err := demo.conn.Search(searchRequest)
	if err != nil {
		return err
	}

	if len(sr.Entries) != 1 {
		return fmt.Errorf("User %s does not exist or too many entries returned", username)
	}

	userdn := sr.Entries[0].DN //GetAttributeValue("userPrincipalName")

	// Bind as the user to verify their password
	err = demo.conn.Bind(userdn, demo.bindpassword)

	defer demo.bindAsReadOnlyUser(false)

	if err != nil {
		return err
	}

	return nil
}

func (demo *LdapDemo) bindAsReadOnlyUser(useGC bool) error {
	// Rebind as the read only user for any futher queries
	if !useGC {
		if demo.conn != nil {
			return demo.conn.Bind("", demo.bindpassword)
		}
		return fmt.Errorf("GFY")
	}
	if demo.gcConn != nil {
		return demo.gcConn.Bind("", demo.bindpassword)
	}
	return fmt.Errorf("GFY")
}

func demoMode(domain string, username string, password string, testuser string, othertestuser string, useSSL bool, verifySSLCert bool) {

	ldapdemo := NewLdapDemo(domain, 389, username, password, false, verifySSLCert)

	log.Printf("dialing to ldap %s", domain)
	err := ldapdemo.ConnectToAD()
	if err != nil {
		log.Fatal(err)
	}
	defer ldapdemo.Disconnect()
	// log.Print("Get domain list")
	// domains, err := ldapdemo.getDomainList()
	// if err != nil {
	// 	return
	// }
	// for _, domain := range domains {
	// 	fmt.Printf("--------search for users on %s---------\n", domain.GetAttributeValue("dnsRoot"))
	// 	ldapdemo.searchForGroups(domain.GetAttributeValue("nCName"), ("*api*"))
	// }
	log.Println("----------")
	log.Println("----------")
	log.Println("----------")
	log.Println("Get with blank search path")
	log.Println("----------")
	log.Println("----------")
	log.Println("----------")

	ldapdemo.searchForGroups("", ("TestGroup*"))

}
