import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useAutoSave } from '../useAutoSave';
import { useAssessmentStore } from '@/store/assessmentStore';
import { apiService } from '@/services/api';

// Mock dependencies
vi.mock('@/services/api');
vi.mock('@/store/assessmentStore');

describe('useAutoSave', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();

    // Mock store
    (useAssessmentStore as any).mockReturnValue({
      isDirty: false,
      responses: new Map(),
      setIsDirty: vi.fn(),
      setLastSavedAt: vi.fn(),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not save when not dirty', async () => {
    const mockUpdateAssessment = vi.spyOn(apiService, 'updateAssessment');

    renderHook(() => useAutoSave('test-id', true));

    act(() => {
      vi.advanceTimersByTime(30000);
    });

    expect(mockUpdateAssessment).not.toHaveBeenCalled();
  });

  it.skip('should save after 30 seconds when dirty', { timeout: 60000 }, async () => {
    const mockUpdateAssessment = vi.spyOn(apiService, 'updateAssessment').mockResolvedValue({
      assessmentId: 'test-id',
      status: 'in_progress',
      progress: 50,
      updatedAt: new Date().toISOString(),
      savedResponses: 1,
    });

    const responses = new Map();
    responses.set('q1', { questionId: 'q1', answer: 'test' });

    (useAssessmentStore as any).mockReturnValue({
      isDirty: true,
      responses,
      setIsDirty: vi.fn(),
      setLastSavedAt: vi.fn(),
    });

    renderHook(() => useAutoSave('test-id', true));

    act(() => {
      vi.advanceTimersByTime(30000);
    });

    await waitFor(() => {
      expect(mockUpdateAssessment).toHaveBeenCalledWith('test-id', {
        responses: [{ questionId: 'q1', answer: 'test' }],
      });
    });
  });

  it.skip('should debounce multiple changes', { timeout: 60000 }, async () => {
    const mockUpdateAssessment = vi.spyOn(apiService, 'updateAssessment').mockResolvedValue({
      assessmentId: 'test-id',
      status: 'in_progress',
      progress: 50,
      updatedAt: new Date().toISOString(),
      savedResponses: 1,
    });

    (useAssessmentStore as any).mockReturnValue({
      isDirty: true,
      responses: new Map(),
      setIsDirty: vi.fn(),
      setLastSavedAt: vi.fn(),
    });

    const { rerender } = renderHook(() => useAutoSave('test-id', true));

    // Advance timer partially
    act(() => {
      vi.advanceTimersByTime(20000);
    });

    // Change happens, timer should reset
    rerender();

    // Advance another 20 seconds (only 20s since last change)
    act(() => {
      vi.advanceTimersByTime(20000);
    });

    // Should not have saved yet
    expect(mockUpdateAssessment).not.toHaveBeenCalled();

    // Advance final 10 seconds (30s total since last change)
    act(() => {
      vi.advanceTimersByTime(10000);
    });

    // Now it should save
    await waitFor(() => {
      expect(mockUpdateAssessment).toHaveBeenCalledTimes(1);
    });
  });
});
