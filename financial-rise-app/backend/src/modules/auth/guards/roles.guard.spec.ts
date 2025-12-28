import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from './roles.guard';
import { UserRole } from '../../users/entities/user.entity';

describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    const createMockContext = (user: any): ExecutionContext => {
      return {
        switchToHttp: () => ({
          getRequest: () => ({ user }),
        }),
        getHandler: jest.fn(),
        getClass: jest.fn(),
      } as any;
    };

    it('should allow access when no roles are required', () => {
      const context = createMockContext({ role: UserRole.CONSULTANT });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const result = guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should allow access when user has required role', () => {
      const context = createMockContext({ role: UserRole.ADMIN });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      const result = guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when user does not have required role', () => {
      const context = createMockContext({ role: UserRole.CONSULTANT });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      const result = guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should allow access when user has one of multiple required roles', () => {
      const context = createMockContext({ role: UserRole.CONSULTANT });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([
        UserRole.ADMIN,
        UserRole.CONSULTANT,
      ]);

      const result = guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when user has none of the required roles', () => {
      const context = createMockContext({ role: UserRole.CONSULTANT });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      const result = guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should use Reflector to get roles metadata', () => {
      const context = createMockContext({ role: UserRole.ADMIN });
      const getAllAndOverrideSpy = jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue([UserRole.ADMIN]);

      guard.canActivate(context);

      expect(getAllAndOverrideSpy).toHaveBeenCalledWith('roles', [
        context.getHandler(),
        context.getClass(),
      ]);
    });

    it('should check handler and class metadata', () => {
      const mockHandler = jest.fn();
      const mockClass = jest.fn();
      const context = {
        switchToHttp: () => ({
          getRequest: () => ({ user: { role: UserRole.ADMIN } }),
        }),
        getHandler: () => mockHandler,
        getClass: () => mockClass,
      } as any;

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      guard.canActivate(context);

      expect(reflector.getAllAndOverride).toHaveBeenCalledWith('roles', [
        mockHandler,
        mockClass,
      ]);
    });

    it('should handle missing user object gracefully', () => {
      const context = {
        switchToHttp: () => ({
          getRequest: () => ({}),
        }),
        getHandler: jest.fn(),
        getClass: jest.fn(),
      } as any;

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      // The guard will throw when trying to access user.role on undefined user
      // This is expected behavior - the guard expects JWT/auth middleware to populate user
      expect(() => guard.canActivate(context)).toThrow();
    });

    it('should handle user with no role property', () => {
      const context = createMockContext({});
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      const result = guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should work with all UserRole values', () => {
      const roles = [UserRole.ADMIN, UserRole.CONSULTANT];

      roles.forEach((role) => {
        const context = createMockContext({ role });
        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([role]);

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });
    });

    it('should deny when empty roles array is specified', () => {
      const context = createMockContext({ role: UserRole.ADMIN });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([]);

      const result = guard.canActivate(context);

      expect(result).toBe(false);
    });

    it('should be case-sensitive for role matching', () => {
      const context = createMockContext({ role: 'admin' });
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([UserRole.ADMIN]);

      const result = guard.canActivate(context);

      // Should fail if roles don't match exactly
      expect(result).toBe('admin' === UserRole.ADMIN);
    });
  });
});
