import { drizzle } from 'drizzle-orm/neon-http';
import { neon, neonConfig } from '@neondatabase/serverless';
import ws from 'ws';
import { tables } from '~/server/database/client';
import type * as schema from '~~/server/database/schema';

neonConfig.webSocketConstructor = ws;
// Optional for Edge environments (Vercel, Cloudflare, etc.):
// neonConfig.poolQueryViaFetch = true;

const sql = neon(process.env.DATABASE_URL!);
export const db = drizzle(sql, { schema });

// Optionally export tables for convenience
export { tables };