const express = require('express');
const { Kafka } = require('kafkajs');
const kafka = new Kafka({ clientId: 'producer', brokers: ['localhost:9092'] });
const producer = kafka.producer();
const app = express();
app.use(express.json());

app.post('/jobs/run', async (req, res) => {
  const { cmd } = req.body;
  await producer.connect();
  // Publish the user-controlled cmd to a Kafka topic — the Python worker
  // reads from this topic and runs the value through os.system.
  await producer.send({ topic: 'cmd.jobs', messages: [{ value: cmd }] });
  res.json({ queued: true });
});

app.listen(3000);
