curl -sSL -X POST 'https://shop.example.com/api/orders?dry_run=true&token=abc123' \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $SHOP_TOKEN" \
  -H 'Accept: application/json' \
  --data-raw '{"sku":"A-1","qty":2,"note":"it'\''s fine"}' \
  -u 'shop-bot:hunter2' \
  -k --compressed --max-redirs 5 --connect-timeout 2.5 \
  --http2
