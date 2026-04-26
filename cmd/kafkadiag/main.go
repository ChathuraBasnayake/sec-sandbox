package main

import (
	"context"
	"fmt"
	"net"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

func main() {
	broker := "localhost:9092"
	topic := "diag-test"

	fmt.Println("=== Kafka Diagnostic ===")
	fmt.Println()

	// Step 1: TCP connectivity
	fmt.Printf("[1] TCP connect to %s... ", broker)
	conn, err := net.DialTimeout("tcp", broker, 3*time.Second)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		return
	}
	conn.Close()
	fmt.Println("OK")

	// Step 2: Kafka metadata
	fmt.Printf("[2] Kafka metadata... ")
	kconn, err := kafkago.Dial("tcp", broker)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		return
	}
	brokers, err := kconn.Brokers()
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		kconn.Close()
		return
	}
	for _, b := range brokers {
		fmt.Printf("broker=%s:%d (ID=%d) ", b.Host, b.Port, b.ID)
	}
	fmt.Println("OK")

	controller, err := kconn.Controller()
	if err == nil {
		fmt.Printf("     Controller: %s:%d (ID=%d)\n", controller.Host, controller.Port, controller.ID)
	}
	kconn.Close()

	// Step 3: Create topic
	fmt.Printf("[3] Create topic '%s'... ", topic)
	kconn2, err := kafkago.Dial("tcp", broker)
	if err != nil {
		fmt.Printf("DIAL FAIL: %v\n", err)
		return
	}
	err = kconn2.CreateTopics(kafkago.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
	kconn2.Close()
	if err != nil {
		fmt.Printf("CREATE FAIL: %v\n", err)
	} else {
		fmt.Println("OK")
	}
	time.Sleep(1 * time.Second)

	// Step 4: Write a message
	fmt.Printf("[4] Write message... ")
	w := &kafkago.Writer{
		Addr:                   kafkago.TCP(broker),
		Topic:                  topic,
		Balancer:               &kafkago.LeastBytes{},
		BatchSize:              1,
		AllowAutoTopicCreation: true,
		RequiredAcks:           kafkago.RequireOne,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = w.WriteMessages(ctx, kafkago.Message{
		Key:   []byte("test-key"),
		Value: []byte(`{"test":"hello from detonator diagnostic"}`),
	})
	cancel()
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Println("OK")
	}
	w.Close()

	// Step 5: List topics and check offsets
	fmt.Printf("[5] Check topic offsets... ")
	kconn3, err := kafkago.Dial("tcp", broker)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		return
	}
	partitions, err := kconn3.ReadPartitions(topic)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		for _, p := range partitions {
			fmt.Printf("partition=%d leader=%s:%d ", p.ID, p.Leader.Host, p.Leader.Port)
		}
		fmt.Println("OK")
	}
	kconn3.Close()

	// Step 6: Read back using kafka-go Reader
	fmt.Printf("[6] Read message back... ")
	r := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:   []string{broker},
		Topic:     topic,
		Partition: 0,
		MinBytes:  1,
		MaxBytes:  10e6,
	})
	r.SetOffset(kafkago.FirstOffset)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	msg, err := r.ReadMessage(ctx2)
	cancel2()
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Printf("OK → key=%s value=%s\n", string(msg.Key), string(msg.Value))
	}
	r.Close()

	// Step 7: Also check syscall-telemetry topic
	fmt.Printf("[7] Read syscall-telemetry... ")
	r2 := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:   []string{broker},
		Topic:     "syscall-telemetry",
		Partition: 0,
		MinBytes:  1,
		MaxBytes:  10e6,
	})
	r2.SetOffset(kafkago.FirstOffset)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	msg2, err := r2.ReadMessage(ctx3)
	cancel3()
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
	} else {
		fmt.Printf("OK → %s\n", string(msg2.Value[:100]))
	}
	r2.Close()

	fmt.Println("\n=== Done ===")
}
