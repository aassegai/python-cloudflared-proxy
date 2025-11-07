python src/http_proxy.py --mode server \
--listen-port 9000 \
--target-url http://localhost:8001 \
--key 32_bit_encryption_key_1234567890 \
--iv 16_bit_key_123456 \
--logs-path "../logs_cloudflared/server.log"