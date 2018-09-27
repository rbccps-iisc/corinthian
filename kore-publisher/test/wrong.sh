#curl -k -vvv https://127.0.0.1:8888/publish -H 'id: xguest' -H 'apikey: guest' -H 'to: amq.topic' -H 'topic: data' -H 'message: hello'
curl -k -vvv https://127.0.0.1:8888/publish -H 'id: guest' -H 'apikey: guest' -H 'to: xxxamqx.topic' -H 'topic: data' -H 'message: hello'
