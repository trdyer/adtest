package main

import (
	"fmt"

	libadclient "github.com/paleg/libadclient"
)

func getGroups() {
	if groups, err := libadclient.GetGroups(); err == nil {
		for _, group := range groups {
			getUsersInGroup(group)
		}
	}
}

func getUsersInGroup(group string) {
	if users, err := libadclient.GetUsersInGroup(group, true); err == nil {
		fmt.Printf("\t\tUsers in '%v':\n", group)
		for _, user := range users {
			fmt.Printf("\t\t\t%v\n", user)
		}
	}
}

func getGroupsInOU(ou string) {
	if groups, err := libadclient.GetGroupsInOU(ou, 1); err == nil {
		fmt.Printf("\tGroups in '%v':\n", ou)
		for _, group := range groups {
			getUsersInGroup(group)
		}
	}
}

func getOUs() {
	if ous, err := libadclient.GetOUs(); err == nil {
		for _, ou := range ous {
			fmt.Printf("Found OU: %v\n", ou)
			getGroupsInOU(ou)
			// getOUsinOU(ou)
		}
	}
}

func getOUsinOU(ou string) {
	if ous, err := libadclient.GetOUsInOU(ou, 1); err == nil {
		for _, ou := range ous {
			fmt.Printf("Found OU: %v\n", ou)
			getGroupsInOU(ou)
		}
	}
}
