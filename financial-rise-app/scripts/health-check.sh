#!/bin/bash
#
# Financial RISE - Health Check Script
# Verifies that all services are running and healthy
#

set -e

BACKEND_URL="${BACKEND_URL:-http://localhost:4000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:80}"
MAX_RETRIES=30
RETRY_INTERVAL=10

echo "======================================"
echo "Financial RISE Health Check"
echo "======================================"

# Function to check HTTP endpoint
check_endpoint() {
    local url=$1
    local name=$2
    local retries=0

    echo ""
    echo "Checking $name at $url..."

    while [ $retries -lt $MAX_RETRIES ]; do
        if curl -f -s -o /dev/null -w "%{http_code}" $url | grep -q "200"; then
            echo "✅ $name is healthy"
            return 0
        fi

        retries=$((retries + 1))
        if [ $retries -lt $MAX_RETRIES ]; then
            echo "⏳ Attempt $retries/$MAX_RETRIES - $name not ready yet, waiting ${RETRY_INTERVAL}s..."
            sleep $RETRY_INTERVAL
        fi
    done

    echo "❌ $name health check failed after $MAX_RETRIES attempts"
    return 1
}

# Check backend health endpoint
check_endpoint "$BACKEND_URL/api/v1/health" "Backend"
BACKEND_STATUS=$?

# Check frontend
check_endpoint "$FRONTEND_URL" "Frontend"
FRONTEND_STATUS=$?

# Check Docker containers
echo ""
echo "Checking Docker containers..."
COMPOSE_FILES="-f /opt/financial-rise/docker-compose.yml -f /opt/financial-rise/docker-compose.prod.yml"

# Check if backend container is running
if docker compose $COMPOSE_FILES ps backend | grep -q "Up"; then
    echo "✅ Backend container is running"
else
    echo "❌ Backend container is not running"
    BACKEND_STATUS=1
fi

# Check if frontend container is running
if docker compose $COMPOSE_FILES ps frontend | grep -q "Up"; then
    echo "✅ Frontend container is running"
else
    echo "❌ Frontend container is not running"
    FRONTEND_STATUS=1
fi

# Check if redis container is running
if docker compose $COMPOSE_FILES ps redis | grep -q "Up"; then
    echo "✅ Redis container is running"
else
    echo "⚠️  Redis container is not running"
fi

echo ""
echo "======================================"

# Overall status
if [ $BACKEND_STATUS -eq 0 ] && [ $FRONTEND_STATUS -eq 0 ]; then
    echo "✅ All health checks passed"
    echo "======================================"
    exit 0
else
    echo "❌ Some health checks failed"
    echo "======================================"
    exit 1
fi
