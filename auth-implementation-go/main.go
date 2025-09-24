package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"login/handlers"
	"login/structs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/rs/cors"
)

func main() {

	var config structs.Config

	configFile, err := os.Open("/login/config.json")
	if err != nil {
		log.Default().Fatal(err.Error())
	}

	fileData, _ := io.ReadAll(configFile)

	err = json.Unmarshal(fileData, &config)
	if err != nil {
		log.Default().Fatal(err.Error())
	}

	_ = configFile.Close()

retry:

	postgresClient, err := sql.Open("postgres", config.PostgresURL)
	if err != nil {
		log.Default().Print(err.Error())
		time.Sleep(time.Minute)

		goto retry
	}

	_, err = postgresClient.Exec(`
		CREATE SCHEMA IF NOT EXISTS public;

		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			created_at TIMESTAMP DEFAULT NULL,
			updated_at TIMESTAMP DEFAULT NULL,
			deleted_at TIMESTAMP DEFAULT NULL,
			user_id TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			name TEXT NULL,
			password TEXT NULL,
			salt TEXT NULL
		);

		CREATE TABLE IF NOT EXISTS not_allowed_emails (
			email TEXT NOT NULL
		);

		CREATE UNIQUE INDEX ON users (user_id);
		CREATE UNIQUE INDEX ON users (email);
	`)

	if err != nil {
		log.Default().Fatal(err.Error())
	}

	handlers.HASH_COST = config.HashCost

	http.HandleFunc("/api/v1/auth/refresh", handlers.HandleRefresh(&config))
	http.HandleFunc("/api/v1/auth/send", handlers.SendEmail(postgresClient, &config))
	http.HandleFunc("/api/v1/auth/verify", handlers.VerifyUser(postgresClient, &config))
	http.HandleFunc("/api/v1/auth/login", handlers.LoginUser(postgresClient, &config))
	http.HandleFunc("/api/v1/oauth/url", handlers.GetRedirectURLForOAuth(&config))
	http.HandleFunc("/api/v1/oauth/callback", handlers.HandleOAuthCallback(postgresClient, &config))
	http.HandleFunc("/api/v1/internal/signup", handlers.InternalSignUp(postgresClient, &config))

	server := http.Server{Addr: fmt.Sprintf(":%d", config.ServerPort), Handler: cors.New(cors.Options{
		AllowedOrigins:   config.Cors.Origins,
		AllowedHeaders:   config.Cors.Headers,
		AllowedMethods:   config.Cors.Methods,
		AllowCredentials: config.Cors.AllowCredentials,
	}).Handler(http.DefaultServeMux)}

	go func() {
		err = server.ListenAndServe()
		if err != nil {
			log.Default().Print(err.Error())
		}
	}()

	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGINT, syscall.SIGTERM)
	<-channel

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_ = server.Shutdown(ctx)

	time.Sleep(time.Second * 30)
}
