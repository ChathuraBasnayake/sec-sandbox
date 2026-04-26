package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"detonator/internal/sensor"

	kafkago "github.com/segmentio/kafka-go"
)

// KafkaEvent wraps a SyscallEvent with detonation metadata for the Kafka topic.
type KafkaEvent struct {
	PackageName  string    `json:"package_name"`
	ContainerID  string    `json:"container_id"`
	DetonationID string    `json:"detonation_id"`
	PID          uint32    `json:"pid"`
	PPID         uint32    `json:"ppid"`
	TimestampNs  uint64    `json:"timestamp_ns"`
	EventType    string    `json:"event_type"`
	ProcessName  string    `json:"process_name"`
	Filename     string    `json:"filename"`
	CapturedAt   time.Time `json:"captured_at"`
}

// Producer manages the Kafka writer for streaming syscall telemetry.
type Producer struct {
	writer       *kafkago.Writer
	packageName  string
	containerID  string
	detonationID string
	errCount     int
}

// NewProducer creates a Kafka producer that writes to the given broker and topic.
// It ensures the topic exists and uses synchronous writes for data integrity.
func NewProducer(broker, topic, packageName string) (*Producer, error) {
	// Ensure the topic exists (create if not present)
	if err := ensureTopicExists(broker, topic); err != nil {
		return nil, fmt.Errorf("ensuring topic '%s' exists: %w", topic, err)
	}

	w := &kafkago.Writer{
		Addr:                   kafkago.TCP(broker),
		Topic:                  topic,
		Balancer:               &kafkago.LeastBytes{},
		BatchSize:              1,   // Write each message immediately for reliability
		AllowAutoTopicCreation: true,
		RequiredAcks:           kafkago.RequireOne,
	}

	// Generate a unique detonation ID
	detonationID := fmt.Sprintf("det-%s-%s", time.Now().Format("2006-01-02-150405"), packageName)

	return &Producer{
		writer:       w,
		packageName:  packageName,
		detonationID: detonationID,
	}, nil
}

// ensureTopicExists creates the Kafka topic if it doesn't already exist.
// Uses the broker address directly (not the controller) to avoid Docker hostname issues.
func ensureTopicExists(broker, topic string) error {
	// Parse broker address
	host, portStr, err := net.SplitHostPort(broker)
	if err != nil {
		return fmt.Errorf("parsing broker address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parsing port: %w", err)
	}

	// Connect directly to the broker
	conn, err := kafkago.Dial("tcp", broker)
	if err != nil {
		return fmt.Errorf("connecting to broker %s: %w", broker, err)
	}
	defer conn.Close()

	// Create topic using the same connection (avoids controller hostname resolution issues)
	// We use the broker address directly since in KRaft mode, the broker IS the controller
	controllerConn, err := kafkago.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("connecting to controller: %w", err)
	}
	defer controllerConn.Close()

	err = controllerConn.CreateTopics(kafkago.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	})
	if err != nil {
		// Topic might already exist — that's fine
		return nil
	}

	// Wait a moment for the topic to propagate
	time.Sleep(500 * time.Millisecond)
	return nil
}

// SetContainerID sets the container ID for event metadata.
// Called after the container is created but before events start flowing.
func (p *Producer) SetContainerID(id string) {
	p.containerID = id
}

// Produce serializes a SyscallEvent to JSON and sends it to Kafka.
func (p *Producer) Produce(ctx context.Context, event sensor.SyscallEvent) error {
	kafkaEvent := KafkaEvent{
		PackageName:  p.packageName,
		ContainerID:  p.containerID,
		DetonationID: p.detonationID,
		PID:          event.PID,
		PPID:         event.PPID,
		TimestampNs:  event.TimestampNs,
		EventType:    event.EventType.String(),
		ProcessName:  event.ProcessName,
		Filename:     event.Filename,
		CapturedAt:   time.Now(),
	}

	data, err := json.Marshal(kafkaEvent)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}

	msg := kafkago.Message{
		Key:   []byte(p.detonationID),
		Value: data,
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.errCount++
		return fmt.Errorf("writing to Kafka: %w", err)
	}
	return nil
}

// ErrorCount returns the number of failed writes.
func (p *Producer) ErrorCount() int {
	return p.errCount
}

// DetonationID returns the unique detonation ID for this session.
func (p *Producer) DetonationID() string {
	return p.detonationID
}

// Close flushes pending messages and closes the Kafka writer.
func (p *Producer) Close() error {
	if p.writer != nil {
		return p.writer.Close()
	}
	return nil
}
