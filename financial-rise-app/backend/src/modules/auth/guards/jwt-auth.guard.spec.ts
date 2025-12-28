import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    guard = new JwtAuthGuard();
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should call super.canActivate', () => {
      const mockContext = {} as ExecutionContext;
      const superSpy = jest.spyOn(Object.getPrototypeOf(JwtAuthGuard.prototype), 'canActivate');
      superSpy.mockReturnValue(true);

      guard.canActivate(mockContext);

      expect(superSpy).toHaveBeenCalledWith(mockContext);
    });
  });

  describe('handleRequest', () => {
    it('should return user when valid', () => {
      const mockUser = {
        userId: 'user-123',
        email: 'test@example.com',
        role: 'consultant',
      };

      const result = guard.handleRequest(null, mockUser, null);

      expect(result).toEqual(mockUser);
    });

    it('should throw UnauthorizedException when user is null', () => {
      expect(() => {
        guard.handleRequest(null, null, null);
      }).toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when user is undefined', () => {
      expect(() => {
        guard.handleRequest(null, undefined, null);
      }).toThrow(UnauthorizedException);
    });

    it('should throw custom error message', () => {
      try {
        guard.handleRequest(null, null, null);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.message).toBe('Invalid or expired token');
      }
    });

    it('should throw error if err is provided', () => {
      const customError = new Error('Custom error');

      expect(() => {
        guard.handleRequest(customError, null, null);
      }).toThrow(customError);
    });

    it('should prioritize err over missing user', () => {
      const customError = new UnauthorizedException('Token expired');

      expect(() => {
        guard.handleRequest(customError, null, null);
      }).toThrow('Token expired');
    });

    it('should return user even if info is provided', () => {
      const mockUser = { userId: 'user-123' };
      const info = { message: 'Some info' };

      const result = guard.handleRequest(null, mockUser, info);

      expect(result).toEqual(mockUser);
    });

    it('should throw when user is false', () => {
      expect(() => {
        guard.handleRequest(null, false, null);
      }).toThrow(UnauthorizedException);
    });

    it('should throw when user is 0', () => {
      expect(() => {
        guard.handleRequest(null, 0, null);
      }).toThrow(UnauthorizedException);
    });

    it('should throw when user is empty string', () => {
      expect(() => {
        guard.handleRequest(null, '', null);
      }).toThrow(UnauthorizedException);
    });
  });
});
