package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/IBM/sarama"
)

func main() {
	brokers := []string{"localhost:29092"}
	topic := "boundary-events"

	config := sarama.NewConfig()
	config.Version = sarama.DefaultVersion
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Return.Errors = true

	log.Default().Println("Starting consumer...")
	consumer, err := sarama.NewConsumerGroup(brokers, "boundary-test-consumer", config)
	if err != nil {
		panic(err)
	}
	defer consumer.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGKILL)
	defer cancel()

	if err = consumer.Consume(ctx, []string{topic}, &EventHandler{}); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

type (
	EventHandler struct {
	}
)

func (e *EventHandler) Setup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (e *EventHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	return nil
}

func (e *EventHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	ctx := session.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message := <-claim.Messages():
			if _, err := fmt.Println(string(message.Value)); err != nil {
				return err
			}

			session.MarkMessage(message, "")
		}
	}
}
