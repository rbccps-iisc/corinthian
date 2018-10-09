FROM 	alpine:latest

COPY 	rabbitmq.config /etc/rabbitmq/  

RUN 	apk update && \
    	apk upgrade && \
    	echo "https://nl.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    	apk update && \
  	apk add rabbitmq-server curl tmux && \
  	chmod -R 777 /usr/lib/rabbitmq && \
  	chmod -R 777 /etc && \
  	apk add git build-base openssl libbsd-dev bsd-compat-headers postgresql-dev && \
  	git clone https://github.com/arun-babu/kore && \
  	cd kore && \
  	make NOTLS=1 PGSQL=1 && \
  	make install && \
  	cd .. && \
  	rm -rf kore && \
	apk del --purge git curl && \
  	rabbitmq-plugins enable rabbitmq_management && \
  	rabbitmq-plugins enable rabbitmq_mqtt && \
  	rabbitmq-plugins enable rabbitmq_auth_backend_http 

RUN 	chown -R rabbitmq /usr/lib/rabbitmq/ && \
   	chmod 700 -R /usr/lib/rabbitmq/

CMD 	tail -f /dev/null
