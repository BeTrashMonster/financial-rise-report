/**
 * Unit Tests for ChecklistService
 *
 * Tests all core functionality of the checklist service using TDD approach.
 * Tests are written BEFORE implementation to guide development.
 *
 * @module services/__tests__/checklistService.test.ts
 * @version 1.0
 * @date 2025-12-22
 */

import { ChecklistService } from '../checklistService';
import { ChecklistItem } from '../../models/ChecklistItem';
import { ChecklistEditHistory } from '../../models/ChecklistEditHistory';
import { getReport } from '../reportService';

// Mock dependencies
jest.mock('../reportService');
jest.mock('../../models/ChecklistItem');
jest.mock('../../models/ChecklistEditHistory');

const mockedGetReport = getReport as jest.MockedFunction<typeof getReport>;

describe('ChecklistService', () => {
  let service: ChecklistService;
  const mockAssessmentId = 'assessment-123';
  const mockConsultantId = 'consultant-456';
  const mockClientId = 'client-789';

  beforeEach(() => {
    service = new ChecklistService();
    jest.clearAllMocks();
  });

  describe('getChecklist', () => {
    it('should return empty checklist when no items exist', async () => {
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue([]);

      const result = await service.getChecklist(mockAssessmentId);

      expect(result).toEqual({
        assessment_id: mockAssessmentId,
        total_items: 0,
        completed_items: 0,
        progress_percentage: 0,
        items_by_phase: {
          Stabilize: { total: 0, completed: 0, items: [] },
          Organize: { total: 0, completed: 0, items: [] },
          Build: { total: 0, completed: 0, items: [] },
          Grow: { total: 0, completed: 0, items: [] },
          Systemic: { total: 0, completed: 0, items: [] }
        }
      });
    });

    it('should return checklist grouped by phase', async () => {
      const mockItems = [
        { id: '1', phase: 'Stabilize', is_completed: false, title: 'Item 1' },
        { id: '2', phase: 'Stabilize', is_completed: true, title: 'Item 2' },
        { id: '3', phase: 'Build', is_completed: false, title: 'Item 3' },
        { id: '4', phase: 'Build', is_completed: false, title: 'Item 4' },
        { id: '5', phase: 'Grow', is_completed: true, title: 'Item 5' }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      const result = await service.getChecklist(mockAssessmentId);

      expect(result.total_items).toBe(5);
      expect(result.completed_items).toBe(2);
      expect(result.progress_percentage).toBe(40);
      expect(result.items_by_phase.Stabilize.total).toBe(2);
      expect(result.items_by_phase.Stabilize.completed).toBe(1);
      expect(result.items_by_phase.Build.total).toBe(2);
      expect(result.items_by_phase.Build.completed).toBe(0);
      expect(result.items_by_phase.Grow.total).toBe(1);
      expect(result.items_by_phase.Grow.completed).toBe(1);
    });

    it('should filter by phase when specified', async () => {
      const mockItems = [
        { id: '1', phase: 'Build', is_completed: false, title: 'Item 1' },
        { id: '2', phase: 'Build', is_completed: true, title: 'Item 2' }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      await service.getChecklist(mockAssessmentId, { phase: 'Build' });

      expect(ChecklistItem.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ phase: 'Build' })
        })
      );
    });

    it('should filter by completion status when specified', async () => {
      await service.getChecklist(mockAssessmentId, { completed: true });

      expect(ChecklistItem.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ is_completed: true })
        })
      );
    });

    it('should include deleted items when includeDeleted is true', async () => {
      await service.getChecklist(mockAssessmentId, { includeDeleted: true });

      expect(ChecklistItem.findAll).toHaveBeenCalledWith(
        expect.objectContaining({
          paranoid: false
        })
      );
    });
  });

  describe('autoGenerateChecklist', () => {
    it('should throw error if report not generated', async () => {
      mockedGetReport.mockResolvedValue(null as any);

      await expect(
        service.autoGenerateChecklist(mockAssessmentId, mockConsultantId)
      ).rejects.toThrow('Report must be generated before creating checklist');
    });

    it('should throw conflict error if checklist already exists', async () => {
      mockedGetReport.mockResolvedValue({ data: {} } as any);
      (ChecklistItem.count as jest.Mock).mockResolvedValue(5);

      await expect(
        service.autoGenerateChecklist(mockAssessmentId, mockConsultantId)
      ).rejects.toThrow('Checklist already exists');
    });

    it('should create checklist items from report recommendations', async () => {
      const mockReport = {
        data: {
          recommendations: {
            Stabilize: [
              { title: 'Reconcile accounts', description: 'Review all accounts', priority: 3 }
            ],
            Build: [
              { title: 'Implement SOPs', description: 'Create standard procedures', priority: 2 }
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

      const result = await service.autoGenerateChecklist(mockAssessmentId, mockConsultantId);

      expect(result.items_created).toBe(2);
      expect(ChecklistItem.create).toHaveBeenCalledTimes(2);
      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          assessment_id: mockAssessmentId,
          title: 'Reconcile accounts',
          phase: 'Stabilize',
          auto_generated: true,
          created_by: mockConsultantId
        })
      );
    });

    it('should set correct priority based on primary phase', async () => {
      const mockReport = {
        data: {
          recommendations: {
            Build: [
              { title: 'Primary phase item', description: 'Test', id: 'rec-1' }
            ],
            Grow: [
              { title: 'Adjacent phase item', description: 'Test', id: 'rec-2' }
            ],
            Stabilize: [
              { title: 'Distant phase item', description: 'Test', id: 'rec-3' }
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

      await service.autoGenerateChecklist(mockAssessmentId, mockConsultantId);

      // Primary phase should get priority 3 (high)
      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Primary phase item',
          priority: 3
        })
      );

      // Adjacent phase (Grow is +1 from Build) should get priority 2 (medium)
      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Adjacent phase item',
          priority: 2
        })
      );

      // Distant phase should get priority 1 (low)
      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Distant phase item',
          priority: 1
        })
      );
    });
  });

  describe('createItem', () => {
    it('should create a new checklist item with next sort order', async () => {
      (ChecklistItem.max as jest.Mock).mockResolvedValue(5);
      (ChecklistItem.create as jest.Mock).mockResolvedValue({
        id: 'new-item',
        title: 'New Item',
        sort_order: 6
      });

      const result = await service.createItem({
        assessment_id: mockAssessmentId,
        title: 'New Item',
        phase: 'Build',
        created_by: mockConsultantId
      });

      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          assessment_id: mockAssessmentId,
          title: 'New Item',
          phase: 'Build',
          sort_order: 6,
          created_by: mockConsultantId
        })
      );
    });

    it('should use sort_order 1 when no items exist', async () => {
      (ChecklistItem.max as jest.Mock).mockResolvedValue(null);
      (ChecklistItem.create as jest.Mock).mockResolvedValue({
        id: 'new-item',
        sort_order: 1
      });

      await service.createItem({
        assessment_id: mockAssessmentId,
        title: 'First Item',
        phase: 'Stabilize',
        created_by: mockConsultantId
      });

      expect(ChecklistItem.create).toHaveBeenCalledWith(
        expect.objectContaining({
          sort_order: 1
        })
      );
    });
  });

  describe('updateItem', () => {
    it('should allow consultant to update any field', async () => {
      const mockItem = {
        id: 'item-1',
        title: 'Old Title',
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      await service.updateItem(
        'item-1',
        { title: 'New Title', priority: 3 },
        mockConsultantId,
        'consultant'
      );

      expect(mockItem.update).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'New Title',
          priority: 3,
          updated_by: mockConsultantId
        })
      );
    });

    it('should only allow client to update client_notes', async () => {
      const mockItem = {
        id: 'item-1',
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      await expect(
        service.updateItem(
          'item-1',
          { title: 'New Title', client_notes: 'My notes' },
          mockClientId,
          'client'
        )
      ).rejects.toThrow('Clients can only update notes');
    });

    it('should allow client to update only client_notes', async () => {
      const mockItem = {
        id: 'item-1',
        client_notes: 'Old notes',
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      await service.updateItem(
        'item-1',
        { client_notes: 'New notes' },
        mockClientId,
        'client'
      );

      expect(mockItem.update).toHaveBeenCalledWith(
        expect.objectContaining({
          client_notes: 'New notes',
          client_notes_updated_at: expect.any(Date),
          updated_by: mockClientId
        })
      );
    });

    it('should throw error if item not found', async () => {
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(null);

      await expect(
        service.updateItem('nonexistent', {}, mockConsultantId, 'consultant')
      ).rejects.toThrow('Checklist item not found');
    });
  });

  describe('toggleComplete', () => {
    it('should mark item as complete', async () => {
      const mockItem = {
        id: 'item-1',
        is_completed: false,
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      const result = await service.toggleComplete('item-1', true, mockClientId);

      expect(mockItem.update).toHaveBeenCalledWith({
        is_completed: true,
        completed_at: expect.any(Date),
        completed_by: mockClientId,
        updated_by: mockClientId,
        updated_at: expect.any(Date)
      });
    });

    it('should mark item as incomplete', async () => {
      const mockItem = {
        id: 'item-1',
        is_completed: true,
        completed_at: new Date(),
        completed_by: mockClientId,
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      await service.toggleComplete('item-1', false, mockConsultantId);

      expect(mockItem.update).toHaveBeenCalledWith({
        is_completed: false,
        completed_at: null,
        completed_by: null,
        updated_by: mockConsultantId,
        updated_at: expect.any(Date)
      });
    });

    it('should throw error if item not found', async () => {
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(null);

      await expect(
        service.toggleComplete('nonexistent', true, mockClientId)
      ).rejects.toThrow('Checklist item not found');
    });
  });

  describe('deleteItem', () => {
    it('should soft delete item', async () => {
      const mockItem = {
        id: 'item-1',
        update: jest.fn().mockResolvedValue(true)
      };
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(mockItem);

      await service.deleteItem('item-1', mockConsultantId);

      expect(mockItem.update).toHaveBeenCalledWith({
        deleted_at: expect.any(Date),
        updated_by: mockConsultantId
      });
    });

    it('should throw error if item not found', async () => {
      (ChecklistItem.findByPk as jest.Mock).mockResolvedValue(null);

      await expect(
        service.deleteItem('nonexistent', mockConsultantId)
      ).rejects.toThrow('Checklist item not found');
    });
  });

  describe('reorderItems', () => {
    it('should update sort_order for multiple items', async () => {
      (ChecklistItem.update as jest.Mock).mockResolvedValue([1]);

      const items = [
        { id: 'item-1', sort_order: 0 },
        { id: 'item-2', sort_order: 1 },
        { id: 'item-3', sort_order: 2 }
      ];

      await service.reorderItems(mockAssessmentId, items);

      expect(ChecklistItem.update).toHaveBeenCalledTimes(3);
      expect(ChecklistItem.update).toHaveBeenCalledWith(
        { sort_order: 0 },
        { where: { id: 'item-1', assessment_id: mockAssessmentId } }
      );
      expect(ChecklistItem.update).toHaveBeenCalledWith(
        { sort_order: 1 },
        { where: { id: 'item-2', assessment_id: mockAssessmentId } }
      );
    });
  });

  describe('groupByPhase', () => {
    it('should group items by all phases even if empty', async () => {
      const mockItems = [
        { id: '1', phase: 'Stabilize', is_completed: false },
        { id: '2', phase: 'Build', is_completed: true }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      const result = await service.getChecklist(mockAssessmentId);

      expect(result.items_by_phase).toHaveProperty('Stabilize');
      expect(result.items_by_phase).toHaveProperty('Organize');
      expect(result.items_by_phase).toHaveProperty('Build');
      expect(result.items_by_phase).toHaveProperty('Grow');
      expect(result.items_by_phase).toHaveProperty('Systemic');

      expect(result.items_by_phase.Organize.total).toBe(0);
      expect(result.items_by_phase.Grow.total).toBe(0);
    });
  });

  describe('progress calculation', () => {
    it('should calculate 0% when no items exist', async () => {
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue([]);

      const result = await service.getChecklist(mockAssessmentId);

      expect(result.progress_percentage).toBe(0);
    });

    it('should calculate correct percentage', async () => {
      const mockItems = [
        { id: '1', phase: 'Build', is_completed: true },
        { id: '2', phase: 'Build', is_completed: true },
        { id: '3', phase: 'Build', is_completed: true },
        { id: '4', phase: 'Build', is_completed: false }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      const result = await service.getChecklist(mockAssessmentId);

      expect(result.progress_percentage).toBe(75);
    });

    it('should round percentage to nearest integer', async () => {
      const mockItems = [
        { id: '1', phase: 'Build', is_completed: true },
        { id: '2', phase: 'Build', is_completed: false },
        { id: '3', phase: 'Build', is_completed: false }
      ];
      (ChecklistItem.findAll as jest.Mock).mockResolvedValue(mockItems);

      const result = await service.getChecklist(mockAssessmentId);

      // 1/3 = 33.333... should round to 33
      expect(result.progress_percentage).toBe(33);
    });
  });
});
