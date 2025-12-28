import { Request, Response } from 'express';
import { AdminController } from '../../../src/controllers/AdminController';
import { AdminService } from '../../../src/services/AdminService';
import { UserRole } from '../../../src/database/entities/User';

// Mock AdminService
const mockAdminService = {
  listUsers: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  deleteUser: jest.fn(),
  resetUserPassword: jest.fn(),
  getActivityLogs: jest.fn()
} as unknown as AdminService;

describe('AdminController', () => {
  let adminController: AdminController;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    adminController = new AdminController(mockAdminService);

    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });

    mockRequest = {
      body: {},
      query: {},
      params: {},
      user: {
        userId: 'admin-123',
        email: 'admin@example.com',
        role: UserRole.ADMIN
      }
    };

    mockResponse = {
      status: statusMock,
      json: jsonMock
    };
  });

  describe('listUsers', () => {
    it('should successfully list users with pagination', async () => {
      const mockResult = {
        data: [
          {
            id: 'user-1',
            email: 'user1@example.com',
            role: UserRole.CONSULTANT,
            isActive: true
          },
          {
            id: 'user-2',
            email: 'user2@example.com',
            role: UserRole.ADMIN,
            isActive: true
          }
        ],
        pagination: {
          total: 2,
          page: 1,
          limit: 20,
          totalPages: 1
        }
      };

      (mockAdminService.listUsers as jest.Mock).mockResolvedValue(mockResult);

      await adminController.listUsers(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.listUsers).toHaveBeenCalledWith(
        expect.objectContaining({
          page: undefined,
          limit: undefined,
          role: undefined,
          isActive: undefined,
          search: undefined
        }),
        'admin-123'
      );
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        users: mockResult.data,
        pagination: mockResult.pagination
      });
    });

    it('should handle query parameters correctly', async () => {
      mockRequest.query = {
        page: '2',
        limit: '10',
        role: 'consultant',
        isActive: 'true',
        search: 'test'
      };

      (mockAdminService.listUsers as jest.Mock).mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 2, limit: 10, totalPages: 0 }
      });

      await adminController.listUsers(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.listUsers).toHaveBeenCalledWith(
        {
          page: 2,
          limit: 10,
          role: 'consultant',
          isActive: true,
          search: 'test'
        },
        'admin-123'
      );
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;

      await adminController.listUsers(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.listUsers).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    });

    it('should return 400 for service errors', async () => {
      (mockAdminService.listUsers as jest.Mock).mockRejectedValue(
        new Error('Invalid query parameters')
      );

      await adminController.listUsers(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid query parameters'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      (mockAdminService.listUsers as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.listUsers(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('createUser', () => {
    it('should successfully create a new user', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      const mockUser = {
        id: 'new-user-123',
        email: 'newuser@example.com',
        role: UserRole.CONSULTANT,
        isActive: true,
        createdAt: new Date()
      };

      (mockAdminService.createUser as jest.Mock).mockResolvedValue(mockUser);

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.createUser).toHaveBeenCalledWith(
        {
          email: 'newuser@example.com',
          password: 'SecurePass123!',
          role: UserRole.CONSULTANT
        },
        'admin-123'
      );
      expect(statusMock).toHaveBeenCalledWith(201);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'User created successfully',
        user: mockUser
      });
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.createUser).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    });

    it('should return 409 if email already registered', async () => {
      mockRequest.body = {
        email: 'existing@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      (mockAdminService.createUser as jest.Mock).mockRejectedValue(
        new Error('Email already registered')
      );

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(409);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Conflict',
        message: 'Email already registered'
      });
    });

    it('should return 422 for password validation errors', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'weak',
        role: UserRole.CONSULTANT
      };

      (mockAdminService.createUser as jest.Mock).mockRejectedValue(
        new Error('Password must be at least 12 characters long')
      );

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(422);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Validation Error',
        message: 'Password must be at least 12 characters long'
      });
    });

    it('should return 400 for other errors', async () => {
      mockRequest.body = {
        email: 'invalid',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      (mockAdminService.createUser as jest.Mock).mockRejectedValue(
        new Error('Invalid email format')
      );

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid email format'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      (mockAdminService.createUser as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.createUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('updateUser', () => {
    it('should successfully update a user', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = {
        email: 'updated@example.com',
        isActive: false
      };

      const mockUpdatedUser = {
        id: 'user-123',
        email: 'updated@example.com',
        role: UserRole.CONSULTANT,
        isActive: false,
        updatedAt: new Date()
      };

      (mockAdminService.updateUser as jest.Mock).mockResolvedValue(mockUpdatedUser);

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.updateUser).toHaveBeenCalledWith(
        'user-123',
        {
          email: 'updated@example.com',
          role: undefined,
          isActive: false
        },
        'admin-123'
      );
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'User updated successfully',
        user: mockUpdatedUser
      });
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { email: 'updated@example.com' };

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.updateUser).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should return 404 if user not found', async () => {
      mockRequest.params = { id: 'nonexistent-user' };
      mockRequest.body = { email: 'updated@example.com' };

      (mockAdminService.updateUser as jest.Mock).mockRejectedValue(
        new Error('User not found')
      );

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(404);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Not Found',
        message: 'User not found'
      });
    });

    it('should return 403 for forbidden operations (change own role)', async () => {
      mockRequest.params = { id: 'admin-123' };
      mockRequest.body = { role: UserRole.CONSULTANT };

      (mockAdminService.updateUser as jest.Mock).mockRejectedValue(
        new Error('Cannot change your own role')
      );

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Cannot change your own role'
      });
    });

    it('should return 403 for deactivating last admin', async () => {
      mockRequest.params = { id: 'last-admin-123' };
      mockRequest.body = { isActive: false };

      (mockAdminService.updateUser as jest.Mock).mockRejectedValue(
        new Error('Cannot deactivate the last admin user')
      );

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Cannot deactivate the last admin user'
      });
    });

    it('should return 409 for email conflicts', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { email: 'taken@example.com' };

      (mockAdminService.updateUser as jest.Mock).mockRejectedValue(
        new Error('Email already in use')
      );

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(409);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Conflict',
        message: 'Email already in use'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { email: 'updated@example.com' };

      (mockAdminService.updateUser as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.updateUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('deleteUser', () => {
    it('should successfully delete a user', async () => {
      mockRequest.params = { id: 'user-123' };

      (mockAdminService.deleteUser as jest.Mock).mockResolvedValue(undefined);

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.deleteUser).toHaveBeenCalledWith('user-123', 'admin-123');
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'User deleted successfully'
      });
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;
      mockRequest.params = { id: 'user-123' };

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.deleteUser).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should return 404 if user not found', async () => {
      mockRequest.params = { id: 'nonexistent-user' };

      (mockAdminService.deleteUser as jest.Mock).mockRejectedValue(
        new Error('User not found')
      );

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(404);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Not Found',
        message: 'User not found'
      });
    });

    it('should return 403 when trying to delete own account', async () => {
      mockRequest.params = { id: 'admin-123' };

      (mockAdminService.deleteUser as jest.Mock).mockRejectedValue(
        new Error('Cannot delete your own account')
      );

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Cannot delete your own account'
      });
    });

    it('should return 403 when trying to delete last admin', async () => {
      mockRequest.params = { id: 'last-admin-123' };

      (mockAdminService.deleteUser as jest.Mock).mockRejectedValue(
        new Error('Cannot delete the last admin user')
      );

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Cannot delete the last admin user'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.params = { id: 'user-123' };

      (mockAdminService.deleteUser as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.deleteUser(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('resetUserPassword', () => {
    it('should successfully reset user password', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { newPassword: 'NewSecurePass456!' };

      (mockAdminService.resetUserPassword as jest.Mock).mockResolvedValue(undefined);

      await adminController.resetUserPassword(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.resetUserPassword).toHaveBeenCalledWith(
        'user-123',
        'NewSecurePass456!',
        'admin-123'
      );
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'Password reset successfully'
      });
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { newPassword: 'NewSecurePass456!' };

      await adminController.resetUserPassword(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.resetUserPassword).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should return 404 if user not found', async () => {
      mockRequest.params = { id: 'nonexistent-user' };
      mockRequest.body = { newPassword: 'NewSecurePass456!' };

      (mockAdminService.resetUserPassword as jest.Mock).mockRejectedValue(
        new Error('User not found')
      );

      await adminController.resetUserPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(404);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Not Found',
        message: 'User not found'
      });
    });

    it('should return 422 for weak password', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { newPassword: 'weak' };

      (mockAdminService.resetUserPassword as jest.Mock).mockRejectedValue(
        new Error('Password must be at least 12 characters long')
      );

      await adminController.resetUserPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(422);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Validation Error',
        message: 'Password must be at least 12 characters long'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.params = { id: 'user-123' };
      mockRequest.body = { newPassword: 'NewSecurePass456!' };

      (mockAdminService.resetUserPassword as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.resetUserPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('getActivityLogs', () => {
    it('should successfully retrieve activity logs', async () => {
      const mockResult = {
        data: [
          {
            id: 'log-1',
            userId: 'user-123',
            action: 'user.login',
            createdAt: new Date(),
            ipAddress: '192.168.1.1'
          },
          {
            id: 'log-2',
            userId: 'user-456',
            action: 'user.logout',
            createdAt: new Date(),
            ipAddress: '192.168.1.2'
          }
        ],
        pagination: {
          total: 2,
          page: 1,
          limit: 50,
          totalPages: 1
        }
      };

      (mockAdminService.getActivityLogs as jest.Mock).mockResolvedValue(mockResult);

      await adminController.getActivityLogs(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.getActivityLogs).toHaveBeenCalledWith(
        expect.objectContaining({
          page: undefined,
          limit: undefined,
          userId: undefined,
          action: undefined,
          resourceType: undefined,
          startDate: undefined,
          endDate: undefined
        }),
        'admin-123'
      );
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        logs: mockResult.data,
        pagination: mockResult.pagination
      });
    });

    it('should handle query parameters correctly', async () => {
      mockRequest.query = {
        page: '1',
        limit: '100',
        userId: 'user-123',
        action: 'login',
        resourceType: 'user',
        startDate: '2025-01-01T00:00:00Z',
        endDate: '2025-12-31T23:59:59Z'
      };

      (mockAdminService.getActivityLogs as jest.Mock).mockResolvedValue({
        data: [],
        pagination: { total: 0, page: 1, limit: 100, totalPages: 0 }
      });

      await adminController.getActivityLogs(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.getActivityLogs).toHaveBeenCalledWith(
        {
          page: 1,
          limit: 100,
          userId: 'user-123',
          action: 'login',
          resourceType: 'user',
          startDate: new Date('2025-01-01T00:00:00Z'),
          endDate: new Date('2025-12-31T23:59:59Z')
        },
        'admin-123'
      );
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;

      await adminController.getActivityLogs(mockRequest as Request, mockResponse as Response);

      expect(mockAdminService.getActivityLogs).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
    });

    it('should return 400 for service errors', async () => {
      (mockAdminService.getActivityLogs as jest.Mock).mockRejectedValue(
        new Error('Invalid date format')
      );

      await adminController.getActivityLogs(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid date format'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      (mockAdminService.getActivityLogs as jest.Mock).mockRejectedValue('Unexpected error');

      await adminController.getActivityLogs(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });
});
