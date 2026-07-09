#!/bin/bash

./ds4-server \
  --metal \
  --ctx 1048576 \
  -m glm52.gguf \
  --dist-transport rdma \
  --role coordinator \
  --layers 0:38 \
  --listen 169.254.244.236 1234 \
  --host 192.168.50.141
