import { useEffect, useRef } from 'react';
import { useAssessmentStore } from '@/store/assessmentStore';
import { apiService } from '@/services/api';
import type { AssessmentResponse } from '@/types';

/**
 * Auto-save hook
 * REQ-ASSESS-005: Auto-save every 30 seconds
 * REQ-PERF-004: Auto-save must complete within 2 seconds
 */
export const useAutoSave = (assessmentId: string | null, enabled: boolean = true) => {
  const { isDirty, responses, setIsDirty, setLastSavedAt } = useAssessmentStore();
  const saveTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const isSavingRef = useRef(false);

  const saveResponses = async () => {
    if (!assessmentId || !isDirty || isSavingRef.current) {
      return;
    }

    try {
      isSavingRef.current = true;

      // Convert Map to array
      const responsesToSave: Array<{
        questionId: string;
        answer: any;
        notApplicable?: boolean;
        consultantNotes?: string;
      }> = [];

      responses.forEach((response) => {
        responsesToSave.push({
          questionId: response.questionId,
          answer: response.answer,
          notApplicable: response.notApplicable,
          consultantNotes: response.consultantNotes,
        });
      });

      if (responsesToSave.length === 0) {
        return;
      }

      // Save to backend
      await apiService.updateAssessment(assessmentId, {
        responses: responsesToSave,
      });

      // Update state
      setIsDirty(false);
      setLastSavedAt(new Date());
    } catch (error) {
      console.error('Auto-save failed:', error);
      // Don't clear isDirty so it will retry
    } finally {
      isSavingRef.current = false;
    }
  };

  // Auto-save on dirty state change
  useEffect(() => {
    if (!enabled || !assessmentId) {
      return;
    }

    // Clear existing timeout
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    // Set new timeout if dirty
    if (isDirty) {
      saveTimeoutRef.current = setTimeout(() => {
        saveResponses();
      }, parseInt(import.meta.env.VITE_AUTO_SAVE_DELAY_MS || '30000'));
    }

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, [isDirty, assessmentId, enabled]); // Removed 'responses' - saveResponses captures it via closure

  // Save on page unload
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isDirty && assessmentId) {
        // Cancel debounced save
        if (saveTimeoutRef.current) {
          clearTimeout(saveTimeoutRef.current);
        }

        // Trigger synchronous save
        saveResponses();

        // Show browser warning if there's unsaved data
        e.preventDefault();
        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
        return e.returnValue;
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isDirty, assessmentId]);

  // Manual save function
  const saveNow = () => {
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }
    return saveResponses();
  };

  return {
    saveNow,
    isSaving: isSavingRef.current,
  };
};

export default useAutoSave;
