/**
 * API Route: Health Check
 * Tests database connectivity and provides system status
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase, healthCheck } from '../../../lib/dbConnection';

/**
 * GET /api/health - Check database and system health
 */
export async function GET(request: NextRequest) {
  try {
    const health = await healthCheck();
    
    return NextResponse.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      database: health,
      environment: {
        node_env: process.env.NODE_ENV || 'development',
        has_mongo_uri: !!process.env.MONGO_URI
      }
    });
    
  } catch (error) {
    console.error('Health check failed:', error);
    return NextResponse.json(
      { 
        status: 'error',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        database: { status: 'unhealthy' }
      },
      { status: 500 }
    );
  }
}