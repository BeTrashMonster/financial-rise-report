import app from './app';
import sequelize from './config/database';
import dotenv from 'dotenv';

dotenv.config();

const PORT = process.env.PORT || 3000;

// Test database connection and start server
const startServer = async () => {
  try {
    // Test database connection
    await sequelize.authenticate();
    console.log('✓ Database connection established successfully');

    // Sync database models (development only)
    if (process.env.NODE_ENV === 'development') {
      // await sequelize.sync({ alter: true });
      console.log('✓ Database models synced');
    }

    // Start server
    app.listen(PORT, () => {
      console.log(`
╔════════════════════════════════════════════════╗
║   Financial RISE Report - Backend API         ║
║   Environment: ${process.env.NODE_ENV?.padEnd(31) || 'development'.padEnd(31)}║
║   Port: ${String(PORT).padEnd(39)}║
║   API Version: ${(process.env.API_VERSION || 'v1').padEnd(31)}║
╚════════════════════════════════════════════════╝

Server is running at http://localhost:${PORT}
API endpoints available at http://localhost:${PORT}/api/${process.env.API_VERSION || 'v1'}
Health check: http://localhost:${PORT}/health
      `);
    });
  } catch (error) {
    console.error('Unable to start server:', error);
    process.exit(1);
  }
};

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await sequelize.close();
  process.exit(0);
});

startServer();
