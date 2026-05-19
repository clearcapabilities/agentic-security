import os
from confluent_kafka import Consumer

# Consume from the same Kafka topic 'cmd.jobs' the Node service publishes to.
consumer = Consumer({'bootstrap.servers': 'localhost:9092', 'group.id': 'worker'})
consumer.subscribe(['cmd.jobs'])


def run():
    while True:
        msg = consumer.poll(timeout=1.0)
        if not msg or msg.error():
            continue
        # VULNERABLE: cmd from queue body fed straight into os.system.
        os.system(msg.value().decode('utf-8'))


if __name__ == '__main__':
    run()
