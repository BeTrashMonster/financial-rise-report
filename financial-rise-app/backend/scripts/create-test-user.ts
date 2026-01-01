import { DataSource } from 'typeorm';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
import { resolve } from 'path';

// Load environment variables
dotenv.config({ path: resolve(__dirname, '../.env') });

async function createTestUser() {
  console.log('🔧 Creating test user...');

  // Create database connection
  const dataSource = new DataSource({
    type: 'postgres',
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT || '5432'),
    username: process.env.DATABASE_USER || 'financial_rise',
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME || 'financial_rise_dev',
    ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
    synchronize: false,
    logging: false,
  });

  try {
    await dataSource.initialize();
    console.log('✅ Connected to database');

    // Check if test user already exists
    const existingUser = await dataSource.query(
      `SELECT id, email FROM users WHERE email = $1`,
      ['test@example.com']
    );

    if (existingUser.length > 0) {
      console.log('⚠️  Test user already exists:', existingUser[0]);
      console.log('   Email:', existingUser[0].email);
      console.log('   ID:', existingUser[0].id);
      await dataSource.destroy();
      return;
    }

    // Hash password
    const passwordHash = await bcrypt.hash('testpassword123', 10);
    console.log('🔐 Password hashed');

    // Create test user
    const result = await dataSource.query(
      `INSERT INTO users (
        email,
        password_hash,
        first_name,
        last_name,
        role,
        status,
        created_at,
        updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
      RETURNING id, email, first_name, last_name, role`,
      [
        'test@example.com',
        passwordHash,
        'Test',
        'User',
        'consultant',
        'active'
      ]
    );

    console.log('✅ Test user created successfully!');
    console.log('   Email:', result[0].email);
    console.log('   Name:', result[0].first_name, result[0].last_name);
    console.log('   Role:', result[0].role);
    console.log('   ID:', result[0].id);
    console.log('');
    console.log('📝 Credentials for testing:');
    console.log('   Email: test@example.com');
    console.log('   Password: testpassword123');

    await dataSource.destroy();
    console.log('');
    console.log('✅ Done! You can now run the auth setup script.');
  } catch (error) {
    console.error('❌ Error creating test user:', error);
    await dataSource.destroy();
    process.exit(1);
  }
}

createTestUser();
