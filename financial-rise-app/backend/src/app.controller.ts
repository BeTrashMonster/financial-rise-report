import { Controller, Get } from '@nestjs/common';

/**
 * Application Health Controller
 * Provides basic health check endpoint for monitoring and testing
 */
@Controller()
export class AppController {
  @Get('health')
  getHealth() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'financial-rise-api',
    };
  }
}
