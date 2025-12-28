import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DataSource, DataSourceOptions } from 'typeorm';

export const typeOrmConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: configService.get('DATABASE_HOST', 'localhost'),
  port: configService.get('DATABASE_PORT', 5432),
  username: configService.get('DATABASE_USER', 'financial_rise'),
  password: configService.get('DATABASE_PASSWORD'),
  database: configService.get('DATABASE_NAME', 'financial_rise_db'),
  entities: [__dirname + '/../modules/**/*.entity{.ts,.js}', __dirname + '/../reports/**/*.entity{.ts,.js}'],
  migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
  synchronize: false, // Never use in production
  logging: configService.get('NODE_ENV') === 'development',
  ssl: configService.get('DATABASE_SSL') === 'true' ? {
    rejectUnauthorized: false,
  } : false,
});

// DataSource for migrations
const config = new ConfigService();
const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: config.get('DATABASE_HOST', 'localhost'),
  port: parseInt(config.get('DATABASE_PORT', '5432')),
  username: config.get('DATABASE_USER', 'financial_rise'),
  password: config.get('DATABASE_PASSWORD', 'financial_rise_dev'),
  database: config.get('DATABASE_NAME', 'financial_rise_dev'),
  entities: [__dirname + '/../modules/**/*.entity{.ts,.js}', __dirname + '/../reports/**/*.entity{.ts,.js}'],
  migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
  synchronize: false,
  logging: true,
};

const dataSource = new DataSource(dataSourceOptions);
export default dataSource;
