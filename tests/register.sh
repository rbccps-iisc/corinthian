#!/bin/bash

curl -ik -X POST https://127.0.0.1:8888/register -H 'Content-Type: application/json' -H 'apikey: '$2'' -H 'entity: '$3'' -H 'id: '$1'' -d '{"test":"test"}'
