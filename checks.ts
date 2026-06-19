import { Stripe } from 'stripe';
import Redis from 'ioredis';
import * as net from 'net';

require('dotenv').config()

async function runDiagnostics() {
  console.log('🔍 Starting System Diagnostics...\n');

  // 1. Check Stripe
  console.log('--- 💳 Stripe Check ---');
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey) {
      console.error('❌ STRIPE_SECRET_KEY is missing from .env');
      process.exit(1);
  } else {
    try {
      const stripe = new Stripe(stripeKey, { apiVersion: '2025-12-15.clover' as any });
      const balance = await stripe.balance.retrieve();
      console.log('✅ Stripe Connection: Success (Key is valid)');
    } catch (err: any) {
        console.error(`❌ Stripe Error: ${err.message}`);
        process.exit(1);
    }
  }

  // 2. Check Redis
  console.log('\n--- 🗄️ Redis Check ---');
  const redis = new Redis({
    host: '127.0.0.1',
    port: 6379,
    connectTimeout: 200,
    maxRetriesPerRequest: 2
  });

  try {
    await redis.ping();
    console.log('✅ Redis Connection: Success (Localhost 6379)');
  } catch (err: any) {
      console.error(`❌ Redis Error: Could not connect. Is Redis running?`);
      process.exit(1);
  } finally {
    redis.disconnect();
  }

  // 3. Check Port 8080 Availability
  console.log('\n--- 🌐 Port 8080 Check ---');
  const port = 8080;
  const server = net.createServer();

  const isPortAvailable = new Promise((resolve) => {
    server.once('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
          console.error(`❌ Port ${port} Error: Already in use by another process.`);
          process.exit(1);
      } else {
          console.error(`❌ Port ${port} Error: ${err.message}`);
          process.exit(1);
      }
      resolve(false);
    });

    server.once('listening', () => {
      console.log(`✅ Port ${port}: Available`);
      server.close();
      resolve(true);
    });

    server.listen(port);
  });

  await isPortAvailable;

  console.log('\n--- 🏁 Diagnostics Complete ---');
}

runDiagnostics()