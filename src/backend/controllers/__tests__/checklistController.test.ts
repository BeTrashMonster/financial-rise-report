/**
 * Integration Tests for Checklist API
 *
 * Tests all checklist endpoints with real HTTP requests.
 * Uses supertest for HTTP testing and mocked database.
 *
 * @module controllers/__tests__/checklistController.test.ts
 * @version 1.0
 * @date 2025-12-22
 */

import request from 'supertest';
import app from '../../app';
import { ChecklistItem } from '../../models/ChecklistItem';
import { getReport } from '../../services/reportService';

// Mock dependencies
jest.mock('../../services/reportService');
jest.mock('../../models/ChecklistItem');

const mockedGetReport = getReport as jest.MockedFunction<typeof getReport>;

describe('Checklist API Integration Tests', () => {
  let authToken: string;
  let consultantToken: string;
  let clientToken: string;
  const assessmentId = 'a7b3c4d5-e6f7-8901-2345-6789abcdef01';
  const itemId = 'c1d2e3f4-a5b6-7890-1234-567890abcdef';

  beforeAll(async () => {
    // Set up test authentication tokens
    consultantToken = await getTestAuthToken('consultant');
    clientToken = await getTestAuthToken('client');
    authToken = consultantToken;
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /api/v1/assessments/:id/checklist (auto-generate)', () => {
    it('should auto-generate checklist from report', async () => {
      const mockReport = {
        data: {
          recommendations: {
            Stabilize: [
              { title: 'Reconcile accounts', description: 'Review all', priority: 3, id: 'rec-1' }
            ],
            Build: [
              { title: 'Create SOPs', description: 'Document processes', priority: 2, id: 'rec-2' }
            ]
          },
          primaryPhase: 'Build'
        }
      };

      mockedGetReport.mockResolvedValue(mockReport as any);
      (ChecklistItem.count as jest.Mock).mockResolvedValue(0);
      (ChecklistItem.create as jest.Mock).mockImplementation((data) =>
        Promise.resolve({ ...data, id: 'item-' + Math.random() })
      );
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue([]);

      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ auto_generate: true });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items_created).toBe(2);
      expect(res.body.message).toContain('auto-generated');
    });

    it('should return 400 if report not generated', async () => {
      mockedGetReport.mockResolvedValue(null as any);

      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ auto_generate: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 409 if checklist already exists', async () => {
      mockedGetReport.mockResolvedValue({ data: {} } as any);
      (ChecklistItem.count as jest.Mock).mockResolvedValue(5);

      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ auto_generate: true });

      expect(res.status).toBe(409);
      expect(res.body.error).toContain('already exists');
    });

    it('should return 403 if client tries to auto-generate', async () => {
      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${clientToken}`)
        .send({ auto_generate: true });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('consultants');
    });
  });

  describe('POST /api/v1/assessments/:id/checklist (manual create)', () => {
    it('should create a new checklist item', async () => {
      (ChecklistItem.max as jest.Mock).mockResolvedValue(5);
      (ChecklistItem.create as jest.Mock).mockResolvedValue({
        id: 'new-item-123',
        title: 'New Action Item',
        phase: 'Build',
        sort_order: 6
      });

      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          title: 'New Action Item',
          description: 'Complete this task',
          phase: 'Build',
          priority: 2
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.title).toBe('New Action Item');
    });

    it('should return 400 if title missing', async () => {
      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          phase: 'Build',
          priority: 2
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Title');
    });

    it('should return 400 if phase missing', async () => {
      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          title: 'New Item'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('phase');
    });

    it('should return 400 if phase invalid', async () => {
      const res = await request(app)
        .post(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          title: 'New Item',
          phase: 'InvalidPhase'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeTruthy();
    });
  });

  describe('GET /api/v1/assessments/:id/checklist', () => {
    it('should return checklist for assessment', async () => {
      const mockItems = [
        { id: '1', phase: 'Stabilize', is_completed: false, title: 'Item 1' },
        { id: '2', phase: 'Build', is_completed: true, title: 'Item 2' }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist`)
        .set('Authorization', `Bearer ${consultantToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('items_by_phase');
      expect(res.body.data.total_items).toBe(2);
      expect(res.body.data.completed_items).toBe(1);
    });

    it('should filter by phase when query param provided', async () => {
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue([
        { id: '1', phase: 'Build', is_completed: false, title: 'Item 1' }
      ]);

      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist?phase=Build`)
        .set('Authorization', `Bearer ${consultantToken}`);

      expect(res.status).toBe(200);
      expect(ChecklistItem.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ phase: 'Build' })
        })
      );
    });

    it('should filter by completion status', async () => {
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue([]);

      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist?completed=true`)
        .set('Authorization', `Bearer ${consultantToken}`);

      expect(res.status).toBe(200);
      expect(ChecklistItem.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ is_completed: true })
        })
      );
    });

    it('should return 401 if not authenticated', async () => {
      const res = await request(app)
        .get(`/api/v1/assessments/${assessmentId}/checklist`);

      expect(res.status).toBe(401);
    });
  });

  describe('PATCH /api/v1/checklist/:id', () => {
    it('should allow consultant to update any field', async () => {
      const mockItem = {
        id: itemId,
        title: 'Updated Title',
        priority: 3,
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const res = await request(app)
        .patch(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          title: 'Updated Title',
          priority: 3
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockItem.update).toHaveBeenCalled();
    });

    it('should allow client to update only client_notes', async () => {
      const mockItem = {
        id: itemId,
        client_notes: 'My notes',
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const res = await request(app)
        .patch(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${clientToken}`)
        .send({
          client_notes: 'My notes'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return 403 if client tries to update restricted field', async () => {
      const mockItem = {
        id: itemId,
        update: jest.fn()
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const res = await request(app)
        .patch(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${clientToken}`)
        .send({
          title: 'Trying to change title',
          priority: 3
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('Clients can only update notes');
    });

    it('should return 404 if item not found', async () => {
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(null);

      const res = await request(app)
        .patch(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ title: 'New Title' });

      expect(res.status).toBe(404);
      expect(res.body.error).toContain('not found');
    });
  });

  describe('POST /api/v1/checklist/:id/complete', () => {
    it('should mark item as complete', async () => {
      const mockItem = {
        id: itemId,
        is_completed: true,
        completed_at: new Date(),
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue({
        ...mockItem,
        is_completed: false,
        update: jest.fn().mockResolvedValue(mockItem)
      });

      const res = await request(app)
        .post(`/api/v1/checklist/${itemId}/complete`)
        .set('Authorization', `Bearer ${clientToken}`)
        .send({ completed: true });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should mark item as incomplete', async () => {
      const mockItem = {
        id: itemId,
        is_completed: false,
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const res = await request(app)
        .post(`/api/v1/checklist/${itemId}/complete`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ completed: false });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return 400 if completed field missing', async () => {
      const res = await request(app)
        .post(`/api/v1/checklist/${itemId}/complete`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('should return 400 if completed is not boolean', async () => {
      const res = await request(app)
        .post(`/api/v1/checklist/${itemId}/complete`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ completed: 'yes' });

      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /api/v1/checklist/:id', () => {
    it('should soft delete item (consultant only)', async () => {
      const mockItem = {
        id: itemId,
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const res = await request(app)
        .delete(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${consultantToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('deleted successfully');
    });

    it('should return 403 if client tries to delete', async () => {
      const res = await request(app)
        .delete(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${clientToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('consultants');
    });

    it('should return 404 if item not found', async () => {
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(null);

      const res = await request(app)
        .delete(`/api/v1/checklist/${itemId}`)
        .set('Authorization', `Bearer ${consultantToken}`);

      expect(res.status).toBe(404);
    });
  });

  describe('PATCH /api/v1/assessments/:id/checklist/reorder', () => {
    it('should reorder items (consultant only)', async () => {
      (ChecklistItem.update as jest.Mock).mockResolvedValue([1]);

      const res = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}/checklist/reorder`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          items: [
            { id: 'item-1', sort_order: 0 },
            { id: 'item-2', sort_order: 1 },
            { id: 'item-3', sort_order: 2 }
          ]
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(ChecklistItem.update).toHaveBeenCalledTimes(3);
    });

    it('should return 403 if client tries to reorder', async () => {
      const res = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}/checklist/reorder`)
        .set('Authorization', `Bearer ${clientToken}`)
        .send({
          items: [{ id: 'item-1', sort_order: 0 }]
        });

      expect(res.status).toBe(403);
    });

    it('should return 400 if items array missing', async () => {
      const res = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}/checklist/reorder`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('should return 400 if items array empty', async () => {
      const res = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}/checklist/reorder`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({ items: [] });

      expect(res.status).toBe(400);
    });

    it('should return 400 if item missing required fields', async () => {
      const res = await request(app)
        .patch(`/api/v1/assessments/${assessmentId}/checklist/reorder`)
        .set('Authorization', `Bearer ${consultantToken}`)
        .send({
          items: [{ id: 'item-1' }] // Missing sort_order
        });

      expect(res.status).toBe(400);
    });
  });
});

// Helper function to get test auth token
async function getTestAuthToken(role: string): Promise<string> {
  // Mock implementation - in real tests this would call actual auth endpoint
  return `mock-${role}-token-${Math.random()}`;
}
