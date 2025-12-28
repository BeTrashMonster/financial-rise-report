/**
 * GDPR Article 18 - Processing Restriction Guard Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ProcessingRestrictionGuard } from './processing-restriction.guard';
import { UsersService } from '../../modules/users/users.service';

describe('ProcessingRestrictionGuard', () => {
  let guard: ProcessingRestrictionGuard;
  let usersService: UsersService;
  let reflector: Reflector;

  const mockUsersService = {
    isProcessingRestricted: jest.fn(),
  };

  const mockReflector = {
    getAllAndOverride: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProcessingRestrictionGuard,
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: Reflector,
          useValue: mockReflector,
        },
      ],
    }).compile();

    guard = module.get<ProcessingRestrictionGuard>(ProcessingRestrictionGuard);
    usersService = module.get<UsersService>(UsersService);
    reflector = module.get<Reflector>(Reflector);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const createMockExecutionContext = (user: any, allowWhenRestricted = false): ExecutionContext => {
    mockReflector.getAllAndOverride.mockReturnValue(allowWhenRestricted);

    return {
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
      getHandler: jest.fn(),
      getClass: jest.fn(),
    } as any;
  };

  describe('canActivate', () => {
    it('should allow access for unrestricted users', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' });
      mockUsersService.isProcessingRestricted.mockResolvedValue(false);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(usersService.isProcessingRestricted).toHaveBeenCalledWith('user-123');
    });

    it('should block access for restricted users', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' });
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
      await expect(guard.canActivate(context)).rejects.toThrow(
        /Your account has restricted data processing/,
      );
    });

    it('should include helpful message when blocking restricted users', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' });
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      try {
        await guard.canActivate(context);
        fail('Should have thrown ForbiddenException');
      } catch (error) {
        expect(error.message).toContain('view, export, or delete your data');
        expect(error.message).toContain('lift the processing restriction');
      }
    });

    it('should allow access when endpoint is marked @AllowWhenRestricted', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' }, true);
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      // Should not even check if processing is restricted
      expect(usersService.isProcessingRestricted).not.toHaveBeenCalled();
    });

    it('should allow access when no user in request', async () => {
      const context = createMockExecutionContext(null);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(usersService.isProcessingRestricted).not.toHaveBeenCalled();
    });

    it('should allow access when user object has no userId', async () => {
      const context = createMockExecutionContext({ email: 'test@example.com' });

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(usersService.isProcessingRestricted).not.toHaveBeenCalled();
    });

    it('should check reflector for class-level decorator', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' }, false);
      mockUsersService.isProcessingRestricted.mockResolvedValue(false);

      await guard.canActivate(context);

      expect(reflector.getAllAndOverride).toHaveBeenCalledWith(
        'allowWhenRestricted',
        expect.any(Array),
      );
    });

    it('should handle service errors gracefully', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' });
      mockUsersService.isProcessingRestricted.mockRejectedValue(
        new Error('Database connection failed'),
      );

      await expect(guard.canActivate(context)).rejects.toThrow('Database connection failed');
    });

    it('should work with different user ID formats', async () => {
      const uuidContext = createMockExecutionContext({
        userId: '550e8400-e29b-41d4-a716-446655440000',
      });
      mockUsersService.isProcessingRestricted.mockResolvedValue(false);

      const result = await guard.canActivate(uuidContext);

      expect(result).toBe(true);
      expect(usersService.isProcessingRestricted).toHaveBeenCalledWith(
        '550e8400-e29b-41d4-a716-446655440000',
      );
    });
  });

  describe('Integration scenarios', () => {
    it('should block creating assessments for restricted users', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' });
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
    });

    it('should allow viewing data for restricted users (with decorator)', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' }, true);
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should allow exporting data for restricted users (with decorator)', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' }, true);
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should allow deleting account for restricted users (with decorator)', async () => {
      const context = createMockExecutionContext({ userId: 'user-123' }, true);
      mockUsersService.isProcessingRestricted.mockResolvedValue(true);

      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });
});
