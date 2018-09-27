#!/usr/bin/env python
import pika

i = 0

connection = pika.BlockingConnection(pika.ConnectionParameters(
        host='localhost'))
channel = connection.channel()

result = channel.queue_declare(exclusive=True)
queue_name = result.method.queue

channel.queue_bind(exchange='amq.topic',
                   queue=queue_name, routing_key='#')

print(' [*] Waiting for messages. To exit press CTRL+C')

def callback(ch, method, properties, body):
    global i
    print(" [x] %r" % body, i)
    i = i+1

channel.basic_consume(callback,
                      queue=queue_name,
                      no_ack=True)

channel.start_consuming()
