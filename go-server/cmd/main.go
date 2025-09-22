package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codeshaine/go-server-template/internal/config"
	"github.com/codeshaine/go-server-template/internal/db"
	"github.com/codeshaine/go-server-template/internal/grpc"
	"github.com/codeshaine/go-server-template/internal/rabbitmq"
	"github.com/codeshaine/go-server-template/internal/router"
	"github.com/spf13/viper"
)

// @title						Example API
// @version						1.0
// @description				    This is a sample server.
// @securityDefinitions.apikey	BearerAuth
// @in							header
// @name						Authorization
// @contact.url					example.com
// @BasePath					/
func main() {
	config.LoadConfig()

	_, err := db.GetDBInstace(viper.GetString("db.dsn"))
	if err != nil {
		log.Default().Fatal(err.Error())
	}

	_, err = grpc.NewGreeterClient(viper.GetString("grpc.connection_string"))
	if err != nil {
		log.Default().Fatal(err.Error())
	}

	rabbitmqConn, err := rabbitmq.NewRabbitMQClient(viper.GetString("rabbitmq.url"))
	if err != nil {
		log.Default().Fatal(err.Error())
	}
	defer rabbitmqConn.Close()

	rabbitmqChannel, err := rabbitmq.NewRabbitMQChannel(rabbitmqConn)
	if err != nil {
		log.Default().Fatal(err.Error())
	}

	if err := rabbitmq.DeclareExternalRabbitMqQueues(rabbitmqChannel, rabbitmq.EXAMPLE); err != nil {
		log.Default().Fatal(err.Error())
	}
	defer rabbitmqChannel.Close()

	var server = http.Server{
		Addr:    fmt.Sprintf("%s:%s", viper.GetString("server.host"), viper.GetString("server.port")),
		Handler: router.NewRouter(),
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Default().Fatal(err.Error())
		}
	}()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	<-sigchan

	ctx, cancel := context.WithTimeout(context.Background(), (2 * time.Minute))

	_ = server.Shutdown(ctx)

	cancel()

	time.Sleep(time.Minute * 2)

}
