package main

import (
	"fmt"
	"log"
	"strings"

	ldap "gopkg.in/ldap.v2"
)

func main() {

	demoMode("redacted", "redacted", "redacted", "redacted", "redacted")
	demoMode("redacted", "redacted", "redacted", "redacted", "redacted")

}

const DC_SEPERATOR = ",dc="

type LdapDemo struct {
	conn         *ldap.Conn
	domain       string
	port         int64
	searchBase   string
	binduser     string
	bindpassword string
}

func NewLdapDemo(domain string, port int64, username string, password string) *LdapDemo {
	domainParts := strings.Split(domain, ".")
	searchBase := fmt.Sprintf("dc=%s", strings.Join(domainParts, DC_SEPERATOR))
	return &LdapDemo{
		domain:       domain,
		port:         port,
		searchBase:   searchBase,
		binduser:     username,
		bindpassword: password,
	}
}

func (demo *LdapDemo) ConnectToAD() error {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", demo.domain, demo.port))
	if err != nil {
		return err
	}
	demo.conn = l
	demo.bindAsReadOnlyUser()
	return nil
}

func (demo *LdapDemo) Disconnect() {
	demo.conn.Close()
}

func (demo *LdapDemo) searchForUser(username string, searchBase string) *ldap.Entry {
	if searchBase == "" {
		searchBase = demo.searchBase
	}
	search := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(sAMAccountName=%s)", username), []string{"cn", "givenName", "sn", "mail", "uid", "dn", "memberOf"}, nil)

	searchResults, err := demo.conn.Search(search)

	if err != nil {
		panic(err)
	}
	log.Printf("\nnumber of entries: %d\n", len(searchResults.Entries))
	searchResults.Print()
	return searchResults.Entries[0]
}

func (demo *LdapDemo) searchForGroupsThatUserBelongsTo(searchdn string, searchBase string) {
	if searchBase == "" {
		searchBase = demo.searchBase
	}
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(&(objectClass=group)(member=%s))", searchdn), []string{"dn", "cn", "ou"}, nil)

	sr, err := demo.conn.Search(searchRequest)
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

func (demo *LdapDemo) searchforOUs(searchBase string, indentlevel string) []*ldap.Entry {
	if searchBase == "" {
		searchBase = demo.searchBase
	}
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=organizationalUnit)", []string{"dn", "cn", "ou"}, nil)

	sr, err := demo.conn.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	// sr.Print()
	for _, entry := range sr.Entries {
		ou := entry.GetAttributeValue("ou")
		log.Printf("%sfound ou %s", indentlevel, ou)
		// log.Printf("\t%sget child groups of ou: %s", indentlevel, ou)
		demo.getChildGroups(entry.DN, indentlevel)
		// log.Printf("\t%sgetting child OU's of %s", indentlevel, ou)
		demo.searchforOUs(entry.DN, fmt.Sprintf("\t%s", indentlevel))
	}
	return sr.Entries
}

func (demo *LdapDemo) getChildGroups(searchBase string, indentlevel string) []*ldap.Entry {
	if searchBase == "" {
		searchBase = demo.searchBase
	}
	searchRequest := ldap.NewSearchRequest(searchBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=group)", []string{"dn", "cn", "ou"}, nil)
	sr, err := demo.conn.Search(searchRequest)
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

	defer demo.bindAsReadOnlyUser()

	if err != nil {
		return err
	}

	return nil
}

func (demo *LdapDemo) bindAsReadOnlyUser() error {
	// Rebind as the read only user for any futher queries
	return demo.conn.Bind(fmt.Sprintf("%s@%s", demo.binduser, demo.domain), demo.bindpassword)
}

func demoMode(domain string, username string, password string, testuser string, othertestuser string) {

	ldapdemo := NewLdapDemo(domain, 389, username, password)

	log.Printf("dialing to ldap %s", domain)
	err := ldapdemo.ConnectToAD()
	if err != nil {
		log.Fatal(err)
	}
	defer ldapdemo.Disconnect()

	returnedUser := ldapdemo.searchForUser(username, "")

	ldapdemo.searchForGroupsThatUserBelongsTo(returnedUser.DN, "")
	ldapdemo.searchforOUs("", "")

	err = ldapdemo.authenticateUser("", testuser, "Password1")
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("successfully authenticated as user: %s", testuser)
	}

	err = ldapdemo.authenticateUser("", othertestuser, "Password1")
	if err != nil {
		log.Println(err)
	}
}
