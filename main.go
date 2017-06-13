package main

import (
	"fmt"
	"log"

	ldap "gopkg.in/ldap.v2"

	libadclient "github.com/paleg/libadclient"
)

func main() {
	// main2("test.corp")
	// main2("bt1.com")
	main3()

}

// swagger:route GET /api/stuff
func main2(domain string) {
	libadclient.New()
	defer libadclient.Delete()

	params := libadclient.DefaultADConnParams()
	// login with a domain name
	params.Domain = "test.corp"
	params.Secured = false
	params.Binddn = "<username>"
	params.Bindpw = "<password>"

	params.Timelimit = 60
	params.Nettimeout = 60
	fmt.Printf("------------- login to %v --------------------\n", domain)
	if err := libadclient.Login(params); err != nil {
		fmt.Printf("Failed to AD login: %v\n", err)
		return
	}
	fmt.Println("------------- get ous --------------------")
	getOUs()
	fmt.Println("------------- get groups --------------------")
	getGroups()
	fmt.Println("------------- finished --------------------")
}

func main3() {
	domain := "test.corp"
	search_base := "dc=test,dc=corp"
	username := "<username>"
	password := "<password>"

	bindusername := "<readonly username>"
	bindpassword := "<readonly password>"

	log.Println("dialing to ldap")
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", domain, 389))
	if err != nil {
		log.Fatal(err)
	}

	l.Debug = false
	log.Println("dialed to ldap")

	// First bind with a read only user
	err = l.Bind(fmt.Sprintf("%s@%s", bindusername, domain), bindpassword)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bound as %v\n", bindusername)

	// Rebind as the read only user for any futher queries
	err = l.Bind(fmt.Sprintf("%s@%s", username, domain), password)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bound as %v\n", username)
	searchRequest := ldap.NewSearchRequest(search_base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 0, false, fmt.Sprintf("(memberUid=%s)", username), []string{"dn"}, nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		panic(err)
	}
	// groups := []string{}
	fmt.Printf("looking for groups for user: %s\n", username)
	sr.Print()
	for _, entry := range sr.Entries {
		group := entry.GetAttributeValue("cn")
		fmt.Printf("user %s is in group %s", username, group)
	}

	l.Close()
	log.Println("closed the connection")
}
