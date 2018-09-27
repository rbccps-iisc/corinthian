#curl -X GET -k -vvv https://127.0.0.1:8888/publish -H 'id: guest' -H 'apikey: guest' -H 'to: amq.topic' -H 'topic: data' -H 'message: hello'
#curl -X POST -k -vvv https://127.0.0.1:8888/publish -H 'id: guest' -H 'apikey: guest' -H 'to: amq.topic' -H 'topic: data' -d 'message: hello'
curl -X POST -k -vvv https://127.0.0.1:8888/publish -H 'id: guest' -H 'apikey: guest' -H 'topic: data' -H 'to: amq.topic' -d 'message: hello' 
