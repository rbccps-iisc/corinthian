#!/bin/bash
curl -ik -X GET \
  https://localhost:8888/follow \
  -H 'apikey: '$2"' \
  -H 'id: '$1'' \
  -H 'permission: read-write' \
  -H 'to: '$3'' \
  -H 'topic: #' \
  -H 'validity: 24'
