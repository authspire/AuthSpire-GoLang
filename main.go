package main

import (
	"authspire/authspire"
	"bufio"
	"fmt"
	"os"
	"strings"
)

var name = ""
var userid = ""
var secret = ""
var currentVersion = "1.0"
var publicKey = ""

func logo() {
	logo := `
Yb  dP                        db              
 YbdP  .d8b. 8   8 8d8b      dPYb   88b. 88b. 
  YP   8' .8 8b d8 8P       dPwwYb  8  8 8  8 
  88   ` + "`" + `Y8P' ` + "`" + `Y8P8 8       dP    Yb 88P' 88P' 
                                    8    8    
`

	fmt.Print(logo)
}

func main() {
	authspire.API(name, userid, secret, currentVersion, publicKey) // IMPORTANT FOR API TO WORK
	authspire.InitApp()                                            // Step 1. Initialize your application
	logo()

	fmt.Println("[1] Register")
	fmt.Println("[2] Login")
	fmt.Println("[3] License only")
	fmt.Println("[4] Add Log")

	fmt.Print(">> ")
	reader := bufio.NewReader(os.Stdin)
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)
	fmt.Println()

	if option == "1" {
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		fmt.Print("Password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)
		fmt.Print("License: ")
		license, _ := reader.ReadString('\n')
		license = strings.TrimSpace(license)
		fmt.Print("Email: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)

		registered := authspire.Register(username, password, license, email)
		if registered {
			fmt.Println("Thanks for registering!")
		}
	} else if option == "2" {
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		fmt.Print("Password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		loggedIn := authspire.Login(username, password)
		if loggedIn {
			fmt.Println("Welcome back " + authspire.User.Username)
			fmt.Println()
			fmt.Println(authspire.User.Email)
			fmt.Println(authspire.User.IP)
			fmt.Println(authspire.User.Expires)
			fmt.Println(authspire.User.HWID)
			fmt.Println(authspire.User.Last_Login)
			fmt.Println(authspire.User.Created_At)
			fmt.Println(authspire.User.Variable)
			fmt.Println(authspire.User.Level)
		}
	} else if option == "3" {
		fmt.Print("License: ")
		license, _ := reader.ReadString('\n')
		license = strings.TrimSpace(license)

		if authspire.License(license) {
			fmt.Println("Welcome back " + authspire.User.Username)
			fmt.Println()
			fmt.Println(authspire.User.Email)
			fmt.Println(authspire.User.IP)
			fmt.Println(authspire.User.Expires)
			fmt.Println(authspire.User.HWID)
			fmt.Println(authspire.User.Last_Login)
			fmt.Println(authspire.User.Created_At)
			fmt.Println(authspire.User.Variable)
			fmt.Println(authspire.User.Level)
		}
	} else if option == "4" {
		fmt.Print("Username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		fmt.Print("Action: ")
		action, _ := reader.ReadString('\n')
		action = strings.TrimSpace(action)

		authspire.AddLog(username, action)
		fmt.Println("Log added!")
	}

}
