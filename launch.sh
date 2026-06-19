#!/bin/bash

# --- CONFIGURATION ---
PORT=6379

echo "🔍 Checking if Redis is already running on port $PORT..."

# Check if the port is open
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; then
    echo "✅ Redis is already active on port $PORT. Skipping Docker start."
else
    echo "🚀 Port $PORT is free. Starting new Redis container..."
    docker run -d --name redis-chat -p $PORT:6379 redis:latest
    
    # Wait a moment for Redis to initialize
    sleep 2
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to start Redis container. Ensure Docker is running."
        exit 1
    fi
fi

# --- STEP 2: RUN CHECKS ---
echo "🧪 Running pre-flight checks (checks.ts)..."
npx ts-node checks.ts

# Capture exit code of the checks
CHECK_EXIT=$?
if [ $CHECK_EXIT -ne 0 ]; then
    echo "❌ Pre-flight checks failed (Code: $CHECK_EXIT). Aborting server start."
    exit 1
fi

# --- STEP 3: START SERVER ---
echo "🛰️ All systems green. Launching Server..."
npx ts-node server.ts