package main

import (
	"fmt"
	"log"
	"strings"

	ldap "gopkg.in/ldap.v2"
)

func main() {

	demoMode("redacted", "redacted", "redacted")
	demoMode("redacted", "redacted", "redacted")

}

const DC_SEPERATOR = ",dc="

func demoMode(domain, username, password string) {

	domainParts := strings.Split(domain, ".")
	searchBase := fmt.Sprintf("dc=%s", strings.Join(domainParts, DC_SEPERATOR))
	log.Printf("searchbase is %s", searchBase)

	log.Printf("dialing to ldap %s", domain)
	l, err := connectToAD(domain, 389, username, password)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Printf("bound as %v\n", username)

	log.Printf("\nsearching for %s\n", username)
	returnedUser := searchForUser(l, username, searchBase)

	searchForGroupsThatUserBelongsTo(l, returnedUser.DN, searchBase)

	log.Println("getting top level OU's")

	searchforOUs(l, searchBase, "")

	log.Println("closing the connection")
}

func connectToAD(domain string, port int64, username string, password string) (l *ldap.Conn, err error) {
	l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", domain, 389))
	if err != nil {
		return nil, err
	}
	err = l.Bind(fmt.Sprintf("%s@%s", username, domain), password)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func searchForUser(l *ldap.Conn, username string, searchBase string) *ldap.Entry {
	search := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(sAMAccountName=%s)", username), []string{"cn", "givenName", "sn", "mail", "uid", "dn", "memberOf"}, nil)

	searchResults, err := l.Search(search)

	if err != nil {
		panic(err)
	}
	log.Printf("\nnumber of entries: %d\n", len(searchResults.Entries))
	searchResults.Print()
	return searchResults.Entries[0]
}

func searchForGroupsThatUserBelongsTo(l *ldap.Conn, searchdn string, searchBase string) {
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(&(objectClass=group)(member=%s))", searchdn), []string{"dn", "cn", "ou"}, nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	// groups := []string{}
	log.Printf("\nlooking for groups for user: %s\n", searchdn)
	// sr.Print()
	for _, entry := range sr.Entries {
		group := entry.GetAttributeValue("cn")
		log.Printf("\t\t\tuser %s is in group %v", searchdn, group)
	}
}

func searchforOUs(l *ldap.Conn, searchBase string, indentlevel string) []*ldap.Entry {

	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=organizationalUnit)", []string{"dn", "cn", "ou"}, nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	// sr.Print()
	for _, entry := range sr.Entries {
		ou := entry.GetAttributeValue("ou")
		log.Printf("%sfound ou %s", indentlevel, ou)
		// log.Printf("\t%sget child groups of ou: %s", indentlevel, ou)
		getChildGroups(l, entry.DN, indentlevel)
		// log.Printf("\t%sgetting child OU's of %s", indentlevel, ou)
		searchforOUs(l, entry.DN, fmt.Sprintf("\t%s", indentlevel))
	}
	return sr.Entries
}

func getChildGroups(l *ldap.Conn, searchBase string, indentlevel string) []*ldap.Entry {
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=group)", []string{"dn", "cn", "ou"}, nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	// sr.Print()
	for _, entry := range sr.Entries {
		cn := entry.GetAttributeValue("cn")
		log.Printf("\t%sfound group %s", indentlevel, cn)
	}
	return sr.Entries
}
