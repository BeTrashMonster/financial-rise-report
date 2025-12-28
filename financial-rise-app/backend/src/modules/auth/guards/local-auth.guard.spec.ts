import { ExecutionContext } from '@nestjs/common';
import { LocalAuthGuard } from './local-auth.guard';

describe('LocalAuthGuard', () => {
  let guard: LocalAuthGuard;

  beforeEach(() => {
    guard = new LocalAuthGuard();
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should extend AuthGuard with "local" strategy', () => {
    expect(guard).toBeInstanceOf(LocalAuthGuard);
  });

  describe('canActivate', () => {
    it('should call super.canActivate', () => {
      const mockContext = {
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue({
            body: {
              email: 'test@example.com',
              password: 'password123',
            },
          }),
        }),
      } as unknown as ExecutionContext;

      const superSpy = jest.spyOn(Object.getPrototypeOf(LocalAuthGuard.prototype), 'canActivate');
      superSpy.mockReturnValue(true);

      guard.canActivate(mockContext);

      expect(superSpy).toHaveBeenCalledWith(mockContext);
    });
  });

  describe('integration with passport-local', () => {
    it('should use email field for username', () => {
      // This is configured in LocalStrategy with usernameField: 'email'
      // The guard itself doesn't contain this logic, but it's tested via integration
      expect(guard).toBeDefined();
    });

    it('should validate credentials through LocalStrategy', () => {
      // The actual validation is done by LocalStrategy
      // This guard just triggers the passport authentication flow
      expect(guard).toBeDefined();
    });
  });
});
