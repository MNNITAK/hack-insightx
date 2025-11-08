# Test scenario script

echo "🧪 Running test scenarios..."

echo ""
echo "Scenario 1: Normal web traffic (should be allowed)"
curl -s https://google.com > /dev/null && echo "✅ Google.com - OK"
curl -s https://github.com > /dev/null && echo "✅ GitHub.com - OK"

echo ""
echo "Scenario 2: DNS queries"
nslookup google.com > /dev/null && echo "✅ DNS query - OK"

echo ""
echo "Scenario 3: Local connections"
nc -z localhost 8080 && echo "✅ Collector connection - OK"

echo ""
echo "Scenario 4: Unauthorized service (should be blocked in enforce mode)"
echo "Trying to connect to random port..."
timeout 2 nc -z 8.8.8.8 9999 || echo "✅ Connection attempt logged"

echo ""
echo "Check the dashboard to see all events!"