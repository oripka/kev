import 'dotenv/config';
import { drizzle } from 'drizzle-orm/neon-http';
import { neon, neonConfig } from '@neondatabase/serverless';
import ws from 'ws';
import * as schema from './schema';

// Configure Neon for Node environments
neonConfig.webSocketConstructor = ws;

// Optional: enable for Edge (Vercel, Cloudflare Workers)
// neonConfig.poolQueryViaFetch = true;

// Ensure the environment variable is set
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set in the environment variables.');
}

// Initialize the Neon SQL client
const sql = neon(process.env.DATABASE_URL);

// Initialize Drizzle ORM with your schema
export const db = drizzle(sql, { schema });

// Export schema tables for convenience
export const tables = schema;

export type DbClient = typeof db;