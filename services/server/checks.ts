import { Stripe } from 'stripe';
import * as net from 'net';
import { ping, disconnect } from './services/db/pg';

// Resolves *_FILE secrets and DATABASE_URL before the pool is constructed.
import './lib/config';

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

  // 2. Check Postgres
  console.log('\n--- 🗄️ Postgres Check ---');
  try {
    await ping();
    console.log(`✅ Postgres Connection: Success (${process.env.DATABASE_URL ? 'DATABASE_URL' : 'no DATABASE_URL set'})`);
  } catch (err: any) {
      console.error(`❌ Postgres Error: ${err.message}`);
      console.error('   Is DATABASE_URL set, and has `npm run migrate` been run against it?');
      process.exit(1);
  } finally {
    await disconnect();
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