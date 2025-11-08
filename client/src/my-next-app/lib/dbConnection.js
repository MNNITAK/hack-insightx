/**
 * MongoDB Database Connection Utility
 * Handles connection pooling and database initialization
 */

const mongoose = require('mongoose');

// Connection state
let isConnected = false;


async function connectToDatabase() {
  if (isConnected) {
    console.log('=> Using existing database connection');
    return mongoose.connection;
  }

  try {
    const mongoUri = process.env.MONGO_URI;
    
    if (!mongoUri) {
      throw new Error('MONGO_URI environment variable is not defined');
    }

    console.log('=> Connecting to MongoDB Atlas...');
    
    
  

    // Connect to MongoDB
    await mongoose.connect(mongoUri);
    
    isConnected = true;
    console.log('=> MongoDB Atlas connected successfully');
    
    // Connection event handlers
    mongoose.connection.on('connected', () => {
      console.log('Mongoose connected to MongoDB Atlas');
    });

    mongoose.connection.on('error', (err) => {
      console.error('Mongoose connection error:', err);
      isConnected = false;
    });

    mongoose.connection.on('disconnected', () => {
      console.log('Mongoose disconnected from MongoDB Atlas');
      isConnected = false;
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('Mongoose connection closed through app termination');
      process.exit(0);
    });

    return mongoose.connection;
    
  } catch (error) {
    console.error('=> Database connection failed:', error);
    isConnected = false;
    throw error;
  }
}

/**
 * Disconnect from database
 */
async function disconnectFromDatabase() {
  if (!isConnected) {
    return;
  }
  
  try {
    await mongoose.connection.close();
    isConnected = false;
    console.log('=> Disconnected from MongoDB Atlas');
  } catch (error) {
    console.error('=> Error disconnecting from database:', error);
    throw error;
  }
}

/**
 * Get connection status
 */
function getConnectionStatus() {
  return {
    isConnected,
    readyState: mongoose.connection.readyState,
    host: mongoose.connection.host,
    name: mongoose.connection.name
  };
}

/**
 * Health check for database connection
 */
async function healthCheck() {
  try {
    if (!isConnected) {
      await connectToDatabase();
    }
    
    // Simple ping to check connection
    await mongoose.connection.db.admin().ping();
    
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      connection: getConnectionStatus()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
      connection: getConnectionStatus()
    };
  }
}

module.exports = {
  connectToDatabase,
  disconnectFromDatabase,
  getConnectionStatus,
  healthCheck,
  mongoose
};

/*
Usage Examples:

// Basic connection
const { connectToDatabase } = require('./dbConnection');
await connectToDatabase();

// Health check
const { healthCheck } = require('./dbConnection');
const health = await healthCheck();
console.log(health);

// In API routes
const { connectToDatabase } = require('../../../lib/dbConnection');

export default async function handler(req, res) {
  try {
    await connectToDatabase();
    // Your API logic here
  } catch (error) {
    res.status(500).json({ error: 'Database connection failed' });
  }
}
*/