#!/bin/bash
curl -ik -X POST https://127.0.0.1:8888/publish -H 'apikey: '$2'' -H 'id: '$1'' -H 'message-type: '$5'' -H 'to: '$3'' -H 'topic: '$4'' -d $6
