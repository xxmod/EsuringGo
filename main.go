package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	user := flag.String("u", "", "Login User (Phone Number or Other)")
	password := flag.String("p", "", "Login User Password")
	smsCode := flag.String("s", "", "Pre-enter verification code (optional)")
	flag.StringVar(user, "user", "", "Login User (Phone Number or Other)")
	flag.StringVar(password, "password", "", "Login User Password")
	flag.StringVar(smsCode, "sms", "", "Pre-enter verification code (optional)")
	flag.Parse()

	if *user == "" || *password == "" {
		fmt.Println("Usage: esurfing -u <user> -p <password> [-s <sms_code>]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	opts := Options{
		LoginUser:     *user,
		LoginPassword: *password,
		SMSCode:       *smsCode,
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[Main] Starting ESurfing Go client")
	log.Printf("[Main] User: %s", *user)

	states := NewStates()
	session := NewSession()
	client := NewClient(opts, states, session)

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if states.IsRunning() {
			states.SetRunning(false)
		}
		if session.IsInitialized() {
			if states.IsLogged() {
				client.Term()
			}
			session.Free()
		}
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	states.RefreshStates()
	log.Printf("[Main] Client-ID: %s", states.GetClientID())
	log.Printf("[Main] MAC: %s", states.GetMacAddress())
	client.Run()
}
