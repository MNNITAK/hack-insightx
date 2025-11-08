echo "🌐 Generating test network traffic..."

while true; do
    # Web requests
    curl -s https://example.com > /dev/null
    sleep 2
    
    # Different process
    wget -q -O /dev/null https://google.com
    sleep 2
    
    # Local connection
    nc -z localhost 8080
    sleep 2
    
    echo "🔄 Traffic generated at $(date)"
    sleep 5
done