package rabbitmq

import (
	"fmt"

	amqp "github.com/rabbitmq/amqp091-go"
)

type QueueName string

const (
	EXAMPLE QueueName = "example"
)

func NewRabbitMQClient(connUrl string) (*amqp.Connection, error) {

	if connUrl == "" {
		return nil, fmt.Errorf("rabbitmq URL is not configured")
	}

	conn, err := amqp.Dial(connUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	return conn, nil
}

func NewRabbitMQChannel(conn *amqp.Connection) (*amqp.Channel, error) {
	ch, err := conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("failed to open RabbitMQ channel: %w", err)
	}
	return ch, nil
}

func DeclareExternalRabbitMqQueues(ch *amqp.Channel, queueName QueueName) error {
	_, err := ch.QueueDeclare(string(queueName), true, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("failed to consume: %w", err)
	}
	return nil
}
