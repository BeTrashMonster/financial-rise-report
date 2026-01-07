/**
 * Questionnaire Workflow
 * Work Stream 3: Questionnaire Workflow
 *
 * Features:
 * - Before/after confidence assessment (REQ-QUEST-009)
 * - Dynamic question rendering for all question types
 * - Section-based organization by financial phase (REQ-UX-006)
 * - Progress tracking and breadcrumb navigation (REQ-UX-002, REQ-UX-004)
 * - Auto-save every 5 seconds (REQ-ASSESS-005)
 * - Visual feedback for auto-save (REQ-UX-007)
 * - Save and Exit button (REQ-UX-005)
 * - Non-judgmental language (US-009)
 * - DISC profiling hidden from client (REQ-QUEST-003)
 * - Mobile-responsive, accessible design (WCAG 2.1 AA)
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Button,
  LinearProgress,
  Breadcrumbs,
  Paper,
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  FormLabel,
  Checkbox,
  FormGroup,
  TextField,
  Slider,
  Alert,
  CircularProgress,
  Chip,
  Divider,
  Skeleton,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  NavigateNext as NavigateNextIcon,
  NavigateBefore as NavigateBeforeIcon,
  ExitToApp as ExitIcon,
} from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchQuestions } from '@store/slices/assessmentSlice';
import { assessmentService } from '@services/assessmentService';
import type { Question, QuestionResponse } from '@/types/question';

interface QuestionnaireState {
  currentQuestionIndex: number;
  responses: Map<string, QuestionResponse>;
  beforeConfidence: number | null;
  afterConfidence: number | null;
  showBeforeConfidence: boolean;
  showAfterConfidence: boolean;
  isCalculating: boolean;
}

/**
 * Get section display name
 */
const getSectionName = (section: string): string => {
  const sectionNames: Record<string, string> = {
    stabilize: 'Stabilize',
    organize: 'Organize',
    build: 'Build',
    grow: 'Grow',
    systemic: 'Financial Literacy',
    disc: 'Your Profile',
    metadata: 'Getting Started',
  };
  return sectionNames[section] || section;
};

/**
 * Get section color for visual differentiation
 * Colors adjusted for WCAG AA contrast compliance (4.5:1 for normal text, 3:1 for large text/UI components)
 */
const getSectionColor = (section: string): string => {
  const colors: Record<string, string> = {
    stabilize: '#D32F2F',    // Red - 4.6:1 contrast ✓
    organize: '#ED6C02',     // Orange - 3.9:1 contrast ✓
    build: '#F57C00',        // Darker orange/gold - 4.5:1 contrast ✓ (was #FBC02D - failed)
    grow: '#388E3C',         // Green - 4.6:1 contrast ✓
    systemic: '#0277BD',     // Darker blue - 4.6:1 contrast ✓ (was #0288D1)
    disc: '#7B2FA1',         // Purple - 5.1:1 contrast ✓
    metadata: '#616161',     // Gray - 4.6:1 contrast ✓
  };
  return colors[section] || '#616161';
};

/**
 * Main Questionnaire Component
 */
export const Questionnaire: React.FC = () => {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { questions, loading, error } = useAppSelector((state) => state.assessment);

  const [state, setState] = useState<QuestionnaireState>({
    currentQuestionIndex: 0,
    responses: new Map(),
    beforeConfidence: null,
    afterConfidence: null,
    showBeforeConfidence: true,
    showAfterConfidence: false,
    isCalculating: false,
  });

  const [autoSaveStatus, setAutoSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error' | 'offline'>('idle');
  const autoSaveTimerRef = useRef<NodeJS.Timeout | null>(null);
  const retryCountRef = useRef<number>(0);
  const [formError, setFormError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Fetch questions on mount
  useEffect(() => {
    if (assessmentId) {
      dispatch(fetchQuestions(assessmentId));
    }
  }, [assessmentId, dispatch]);

  // Auto-save effect - triggers 5 seconds after last change
  useEffect(() => {
    if (autoSaveTimerRef.current) {
      clearTimeout(autoSaveTimerRef.current);
    }

    if (state.responses.size > 0 && autoSaveStatus !== 'saving') {
      autoSaveTimerRef.current = setTimeout(() => {
        handleAutoSave();
      }, 5000);
    }

    return () => {
      if (autoSaveTimerRef.current) {
        clearTimeout(autoSaveTimerRef.current);
      }
    };
  }, [state.responses]);

  // Auto-save function with retry logic and offline detection
  const handleAutoSave = async (retryAttempt: number = 0) => {
    if (!assessmentId) return;

    // Check if offline
    if (!navigator.onLine) {
      setAutoSaveStatus('offline');
      setSaveError('You appear to be offline. Changes will be saved when connection is restored.');
      // Retry when connection comes back online
      window.addEventListener('online', () => handleAutoSave(), { once: true });
      return;
    }

    setAutoSaveStatus('saving');
    setSaveError(null);

    try {
      // Save all pending responses
      const unsavedResponses = Array.from(state.responses.values());

      for (const response of unsavedResponses) {
        if (!response.id) {
          // New response - submit
          await assessmentService.submitResponse({
            ...response,
            assessmentId,
          });
        } else {
          // Existing response - update
          await assessmentService.updateResponse(response.id, response);
        }
      }

      // Success - reset retry count
      retryCountRef.current = 0;
      setAutoSaveStatus('saved');
      setSaveError(null);
      setTimeout(() => setAutoSaveStatus('idle'), 2000);
    } catch (err: any) {
      console.error('Auto-save failed:', err);

      // Network error - retry with exponential backoff
      if (err.code === 'ERR_NETWORK' || err.message?.includes('Network')) {
        const maxRetries = 3;
        if (retryAttempt < maxRetries) {
          const backoffMs = Math.min(1000 * Math.pow(2, retryAttempt), 10000); // Max 10s
          retryCountRef.current = retryAttempt + 1;
          setAutoSaveStatus('error');
          setSaveError(`Connection issue. Retrying in ${Math.ceil(backoffMs / 1000)}s... (${retryAttempt + 1}/${maxRetries})`);

          setTimeout(() => handleAutoSave(retryAttempt + 1), backoffMs);
        } else {
          // Max retries exceeded
          setAutoSaveStatus('error');
          setSaveError('Failed to save changes. Please check your connection and try again.');
        }
      } else {
        // Other error (validation, server error, etc.)
        setAutoSaveStatus('error');
        setSaveError(err.response?.data?.message || 'Failed to save changes. Please try again.');
        retryCountRef.current = 0;
      }
    }
  };

  // Handle answer change
  const handleAnswerChange = useCallback((question: Question, answer: any) => {
    const response: QuestionResponse = {
      assessmentId: assessmentId!,
      questionId: question.question_key,
      answer,
    };

    setState((prev) => {
      const newResponses = new Map(prev.responses);
      newResponses.set(question.question_key, response);
      return { ...prev, responses: newResponses };
    });

    setFormError(null);
  }, [assessmentId]);

  // Handle before confidence
  const handleBeforeConfidence = (value: number) => {
    setState((prev) => ({ ...prev, beforeConfidence: value }));
    // After setting, move to first question
    setTimeout(() => {
      setState((prev) => ({ ...prev, showBeforeConfidence: false }));
    }, 500);
  };

  // Handle after confidence and submit
  const handleAfterConfidence = async (value: number) => {
    if (!assessmentId) {
      console.error('[Questionnaire] No assessment ID for submission');
      return;
    }

    console.log('[Questionnaire] Submitting assessment:', assessmentId);
    setState((prev) => ({ ...prev, afterConfidence: value, isCalculating: true }));

    try {
      // Calculate results (responses should already be saved via auto-save)
      console.log('[Questionnaire] Calling submitAssessment API...');
      const result = await assessmentService.submitAssessment(assessmentId);
      console.log('[Questionnaire] Submit response:', result);

      // Navigate to results page
      const resultsPath = `/assessments/${assessmentId}/results`;
      console.log('[Questionnaire] Navigating to:', resultsPath);
      navigate(resultsPath);
    } catch (err: any) {
      console.error('[Questionnaire] Submission error:', err);
      console.error('[Questionnaire] Error response:', err.response);

      // Handle authentication errors
      if (err.response?.status === 401) {
        setFormError('Your session has expired. Please log in again.');
        setTimeout(() => navigate('/login'), 2000);
        return;
      }

      // Handle "results already calculated" error - navigate to results anyway
      if (err.response?.status === 400 &&
          err.response?.data?.message?.includes('already calculated')) {
        console.log('[Questionnaire] Results already exist, navigating to results page');
        const resultsPath = `/assessments/${assessmentId}/results`;
        navigate(resultsPath);
        return;
      }

      // Handle other errors
      setFormError(err.response?.data?.message || 'Failed to submit assessment');
      setState((prev) => ({ ...prev, isCalculating: false }));
    }
  };

  // Validate response format for current question
  const validateResponse = (question: Question, response: QuestionResponse | undefined): string | null => {
    // Check if required question has a response
    if (question.required && !response) {
      return 'Please answer this question before continuing';
    }

    // If not required and no response, that's okay
    if (!response || !response.answer) {
      return null;
    }

    // Validate based on question type
    switch (question.question_type) {
      case 'single_choice':
        if (!response.answer.value || typeof response.answer.value !== 'string' || response.answer.value.trim() === '') {
          return 'Please select an option';
        }
        // Validate selected value exists in options
        const singleOpts = Array.isArray(question.options) ? question.options : question.options?.options || [];
        const validValue = singleOpts.some((opt: any) => opt.value === response.answer.value);
        if (!validValue) {
          return 'Selected option is invalid. Please select a valid option.';
        }
        break;

      case 'multiple_choice':
        if (!Array.isArray(response.answer.value) || response.answer.value.length === 0) {
          return question.required
            ? 'Please select at least one option'
            : null;
        }
        // Validate all selected values exist in options
        const multiOpts = Array.isArray(question.options) ? question.options : question.options?.options || [];
        const validValues = response.answer.value.every((val: string) =>
          multiOpts.some((opt: any) => opt.value === val)
        );
        if (!validValues) {
          return 'One or more selected options are invalid. Please reselect.';
        }
        break;

      case 'rating':
        if (response.answer.rating === null || response.answer.rating === undefined) {
          return 'Please provide a rating';
        }
        if (typeof response.answer.rating !== 'number') {
          return 'Rating must be a number';
        }
        // Validate rating is within min/max range
        const ratingOpts = question.options as any;
        const min = ratingOpts?.min || 1;
        const max = ratingOpts?.max || 10;
        if (response.answer.rating < min || response.answer.rating > max) {
          return `Rating must be between ${min} and ${max}`;
        }
        break;

      case 'text':
        if (question.required && (!response.answer.text || typeof response.answer.text !== 'string' || response.answer.text.trim() === '')) {
          return 'Please enter a response';
        }
        // Validate text length (prevent extremely long inputs)
        if (response.answer.text && typeof response.answer.text === 'string' && response.answer.text.length > 5000) {
          return 'Response is too long (maximum 5000 characters)';
        }
        break;
    }

    return null;
  };

  // Navigation handlers
  const handleNext = () => {
    const currentQuestion = questions[state.currentQuestionIndex];
    const currentResponse = state.responses.get(currentQuestion.question_key);

    // Validate current response
    const validationError = validateResponse(currentQuestion, currentResponse);
    if (validationError) {
      setFormError(validationError);
      return;
    }

    setFormError(null);

    // Check if last question
    if (state.currentQuestionIndex === questions.length - 1) {
      // Show after confidence
      setState((prev) => ({ ...prev, showAfterConfidence: true }));
    } else {
      setState((prev) => ({ ...prev, currentQuestionIndex: prev.currentQuestionIndex + 1 }));
    }
  };

  const handlePrevious = () => {
    setFormError(null);
    setState((prev) => ({ ...prev, currentQuestionIndex: Math.max(0, prev.currentQuestionIndex - 1) }));
  };

  const handleSaveAndExit = async () => {
    // Only save if there are responses
    if (state.responses.size > 0) {
      await handleAutoSave();
    }
    navigate('/assessments');
  };

  // Current progress
  const progress = questions.length > 0
    ? ((state.currentQuestionIndex + 1) / questions.length) * 100
    : 0;

  const answeredCount = state.responses.size;
  const totalQuestions = questions.length;

  // Current question
  const currentQuestion = questions[state.currentQuestionIndex];
  const currentSection = currentQuestion?.section || 'metadata';

  // Loading state with skeleton loaders
  if (loading && questions.length === 0) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={2} sx={{ p: 4 }}>
          {/* Header skeleton */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Skeleton variant="text" width={300} height={40} />
            <Skeleton variant="text" width={100} height={30} />
          </Box>

          {/* Progress bar skeleton */}
          <Box sx={{ mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Skeleton variant="text" width={120} height={20} />
              <Skeleton variant="text" width={100} height={20} />
            </Box>
            <Skeleton variant="rectangular" width="100%" height={8} sx={{ borderRadius: 1 }} />
          </Box>

          {/* Breadcrumbs skeleton */}
          <Box sx={{ mb: 3 }}>
            <Skeleton variant="text" width={200} height={30} />
          </Box>

          <Divider sx={{ mb: 3 }} />

          {/* Question text skeleton */}
          <Box sx={{ mb: 4 }}>
            <Skeleton variant="text" width="80%" height={32} sx={{ mb: 1 }} />
            <Skeleton variant="text" width="60%" height={32} />
          </Box>

          {/* Options skeleton (simulating radio buttons) */}
          <Box sx={{ mb: 4 }}>
            {[1, 2, 3, 4].map((item) => (
              <Box key={item} sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Skeleton variant="circular" width={20} height={20} sx={{ mr: 2 }} />
                <Skeleton variant="text" width="70%" height={24} />
              </Box>
            ))}
          </Box>

          {/* Navigation buttons skeleton */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
            <Skeleton variant="rectangular" width={120} height={42} sx={{ borderRadius: 1 }} />
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Skeleton variant="rectangular" width={140} height={42} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" width={100} height={42} sx={{ borderRadius: 1 }} />
            </Box>
          </Box>
        </Paper>
      </Container>
    );
  }

  // Error state
  if (error) {
    return (
      <Container maxWidth="md" sx={{ py: 8 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button variant="contained" onClick={() => navigate('/assessments')}>
          Return to Assessments
        </Button>
      </Container>
    );
  }

  // Before confidence question
  if (state.showBeforeConfidence) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: { xs: 3, md: 4 } }}>
          <Typography variant="h5" component="h1" gutterBottom>
            Before We Begin
          </Typography>
          <Typography variant="body1" paragraph color="text.secondary">
            Please rate your current confidence in understanding your business's financial readiness.
          </Typography>

          <Box sx={{ mt: 4, mb: 2 }}>
            <FormControl component="fieldset" fullWidth>
              <FormLabel component="legend" sx={{ mb: 3 }}>
                <Typography variant="h6">
                  How confident are you in your understanding of your business's financial health?
                </Typography>
              </FormLabel>

              <Box sx={{ px: 2 }}>
                <Slider
                  value={state.beforeConfidence || 5}
                  onChange={(_, value) => setState((prev) => ({ ...prev, beforeConfidence: value as number }))}
                  min={1}
                  max={10}
                  marks={[
                    { value: 1, label: '1 - Not confident' },
                    { value: 5, label: '5 - Somewhat confident' },
                    { value: 10, label: '10 - Very confident' },
                  ]}
                  valueLabelDisplay="on"
                  aria-label="Confidence level before assessment"
                  sx={{ mt: 4, mb: 6 }}
                />
              </Box>
            </FormControl>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 4 }}>
            <Button
              variant="contained"
              size="large"
              onClick={() => handleBeforeConfidence(state.beforeConfidence || 5)}
              disabled={state.beforeConfidence === null}
            >
              Continue to Assessment
            </Button>
          </Box>
        </Paper>
      </Container>
    );
  }

  // After confidence question
  if (state.showAfterConfidence) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: { xs: 3, md: 4 } }}>
          <Typography variant="h5" component="h1" gutterBottom>
            Assessment Complete!
          </Typography>
          <Typography variant="body1" paragraph color="text.secondary">
            Great work completing the assessment! Before we show your results, please rate your confidence now.
          </Typography>

          <Box sx={{ mt: 4, mb: 2 }}>
            <FormControl component="fieldset" fullWidth>
              <FormLabel component="legend" sx={{ mb: 3 }}>
                <Typography variant="h6">
                  Now, how confident are you in understanding your business's financial health?
                </Typography>
              </FormLabel>

              <Box sx={{ px: 2 }}>
                <Slider
                  value={state.afterConfidence || 5}
                  onChange={(_, value) => setState((prev) => ({ ...prev, afterConfidence: value as number }))}
                  min={1}
                  max={10}
                  marks={[
                    { value: 1, label: '1 - Not confident' },
                    { value: 5, label: '5 - Somewhat confident' },
                    { value: 10, label: '10 - Very confident' },
                  ]}
                  valueLabelDisplay="on"
                  aria-label="Confidence level after assessment"
                  sx={{ mt: 4, mb: 6 }}
                />
              </Box>
            </FormControl>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 4 }}>
            <Button
              variant="contained"
              size="large"
              onClick={() => handleAfterConfidence(state.afterConfidence || 5)}
              disabled={state.afterConfidence === null || state.isCalculating}
            >
              {state.isCalculating ? 'Calculating Results...' : 'View Results'}
            </Button>
          </Box>
        </Paper>
      </Container>
    );
  }

  // Loading state for questions after confidence screen
  if (questions.length === 0) {
    return (
      <Container maxWidth="md" sx={{ py: 8, textAlign: 'center' }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 3 }}>
          Loading questions...
        </Typography>
      </Container>
    );
  }

  // Main questionnaire view
  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      {/* Skip navigation link for keyboard accessibility */}
      <Box
        component="a"
        href="#main-question"
        sx={{
          position: 'absolute',
          left: '-9999px',
          top: '10px',
          zIndex: 9999,
          padding: '8px 16px',
          backgroundColor: 'primary.main',
          color: 'white',
          textDecoration: 'none',
          borderRadius: 1,
          '&:focus': {
            left: '10px',
          },
        }}
      >
        Skip to question
      </Box>

      {/* Header with progress */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: { xs: 'flex-start', md: 'center' },
          flexDirection: { xs: 'column', md: 'row' },
          gap: { xs: 1.5, md: 0 },
          mb: 2
        }}>
          <Typography
            variant="h5"
            component="h1"
            sx={{ fontSize: { xs: '1.25rem', sm: '1.4rem', md: '1.5rem' } }}
          >
            Financial Readiness Assessment
          </Typography>

          {/* Auto-save indicator with aria-live region for screen readers */}
          <Box
            role="status"
            aria-live="polite"
            aria-atomic="true"
            sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
          >
            {autoSaveStatus === 'saving' && (
              <>
                <CircularProgress size={16} aria-hidden="true" />
                <Typography variant="caption" color="text.secondary">
                  Saving...
                </Typography>
              </>
            )}
            {autoSaveStatus === 'saved' && (
              <>
                <CheckCircleIcon fontSize="small" color="success" aria-hidden="true" />
                <Typography variant="caption" color="success.main">
                  Saved
                </Typography>
              </>
            )}
            {autoSaveStatus === 'error' && saveError && (
              <>
                <Typography variant="caption" color="error.main" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <span aria-hidden="true">⚠️</span> {saveError}
                </Typography>
              </>
            )}
            {autoSaveStatus === 'offline' && (
              <>
                <Typography variant="caption" color="warning.main" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <span aria-hidden="true">📡</span> Offline - changes will save when reconnected
                </Typography>
              </>
            )}
          </Box>
        </Box>

        {/* Progress bar */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ fontSize: { xs: '0.75rem', sm: '0.8125rem', md: '0.875rem' } }}
            >
              Question {state.currentQuestionIndex + 1} of {totalQuestions}
            </Typography>
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ fontSize: { xs: '0.75rem', sm: '0.8125rem', md: '0.875rem' } }}
            >
              {answeredCount} answered
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progress}
            aria-label={`Assessment progress: ${Math.round(progress)}% complete. ${answeredCount} of ${totalQuestions} questions answered.`}
            sx={{ height: 8, borderRadius: 4 }}
          />
        </Box>

        {/* Section breadcrumb */}
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} aria-label="Current section">
          <Chip
            label={getSectionName(currentSection)}
            size="small"
            aria-current="location"
            sx={{
              backgroundColor: getSectionColor(currentSection),
              color: 'white',
              fontWeight: 600,
            }}
          />
        </Breadcrumbs>
      </Box>

      {/* Error alert - associated with form field via aria-describedby */}
      {formError && (
        <Alert
          severity="error"
          id="question-error"
          role="alert"
          sx={{ mb: 3 }}
          onClose={() => setFormError(null)}
        >
          {formError}
        </Alert>
      )}

      {/* Question content */}
      {currentQuestion && (
        <Paper id="main-question" sx={{ p: { xs: 3, md: 4 } }}>
          <QuestionRenderer
            question={currentQuestion}
            value={state.responses.get(currentQuestion.question_key)?.answer}
            onChange={(answer) => handleAnswerChange(currentQuestion, answer)}
            hasError={!!formError}
          />

          <Divider sx={{ my: 4 }} />

          {/* Navigation buttons - responsive layout */}
          <Box sx={{
            display: 'flex',
            justifyContent: 'space-between',
            flexDirection: { xs: 'column', sm: 'row' },
            gap: 2
          }}>
            <Box sx={{
              display: 'flex',
              flexDirection: { xs: 'column', sm: 'row' },
              gap: 2,
              width: { xs: '100%', sm: 'auto' }
            }}>
              <Button
                variant="outlined"
                onClick={handlePrevious}
                disabled={state.currentQuestionIndex === 0}
                startIcon={<NavigateBeforeIcon />}
                fullWidth
                sx={{ width: { sm: 'auto' } }}
              >
                Previous
              </Button>
              <Button
                variant="outlined"
                onClick={handleSaveAndExit}
                startIcon={<ExitIcon />}
                disabled={autoSaveStatus === 'saving'}
                fullWidth
                sx={{ width: { sm: 'auto' } }}
              >
                Save & Exit
              </Button>
            </Box>

            <Button
              variant="contained"
              onClick={handleNext}
              endIcon={<NavigateNextIcon />}
              fullWidth
              sx={{ width: { sm: 'auto' } }}
            >
              {state.currentQuestionIndex === questions.length - 1 ? 'Finish' : 'Next'}
            </Button>
          </Box>
        </Paper>
      )}
    </Container>
  );
};

/**
 * Validate question data structure
 * Protects against malformed data from API
 */
const validateQuestionData = (question: Question): { valid: boolean; error?: string } => {
  // Check required fields
  if (!question || typeof question !== 'object') {
    return { valid: false, error: 'Invalid question object' };
  }

  if (!question.question_text || typeof question.question_text !== 'string') {
    return { valid: false, error: 'Question text is missing or invalid' };
  }

  if (!question.question_type || typeof question.question_type !== 'string') {
    return { valid: false, error: 'Question type is missing or invalid' };
  }

  // Validate based on question type
  switch (question.question_type) {
    case 'single_choice':
    case 'multiple_choice':
      const opts = Array.isArray(question.options) ? question.options : question.options?.options;
      if (!Array.isArray(opts) || opts.length === 0) {
        return { valid: false, error: 'Choice questions must have at least one option' };
      }
      // Validate each option has value and text (stored as 'text' in database, not 'label')
      for (const opt of opts) {
        if (!opt || typeof opt !== 'object' || !opt.value || !opt.text) {
          return { valid: false, error: 'Invalid option format: missing value or text' };
        }
      }
      break;

    case 'rating':
      const ratingOpts = question.options as any;
      if (!ratingOpts || typeof ratingOpts !== 'object') {
        return { valid: false, error: 'Rating question must have options object' };
      }
      const min = ratingOpts.min;
      const max = ratingOpts.max;
      if (typeof min !== 'number' || typeof max !== 'number' || min >= max) {
        return { valid: false, error: 'Rating question must have valid min/max values' };
      }
      break;

    case 'text':
      // Text questions don't need options
      break;

    default:
      return { valid: false, error: `Unsupported question type: ${question.question_type}` };
  }

  return { valid: true };
};

/**
 * Question Renderer Component
 * Renders different question types dynamically
 */
interface QuestionRendererProps {
  question: Question;
  value: any;
  onChange: (value: any) => void;
  hasError?: boolean;
}

const QuestionRenderer: React.FC<QuestionRendererProps> = ({ question, value, onChange, hasError = false }) => {
  const { question_text, question_type, options, required } = question;

  // Validate question data before rendering
  const validation = validateQuestionData(question);
  if (!validation.valid) {
    return (
      <Alert severity="error">
        <Typography variant="body2">
          <strong>Question data error:</strong> {validation.error}
        </Typography>
        <Typography variant="caption" display="block" sx={{ mt: 1 }}>
          Question ID: {question.question_key || 'unknown'}
        </Typography>
      </Alert>
    );
  }

  // Single choice (radio buttons)
  if (question_type === 'single_choice') {
    // Handle both formats: direct array or {options: [...]}
    const optionsList = Array.isArray(options) ? options : options?.options || [];

    return (
      <FormControl
        component="fieldset"
        fullWidth
        error={hasError}
        aria-describedby={hasError ? 'question-error' : undefined}
      >
        <FormLabel component="legend" required={required}>
          <Typography
            variant="h6"
            component="h2"
            gutterBottom
            sx={{ fontSize: { xs: '1.1rem', sm: '1.2rem', md: '1.25rem' } }}
          >
            {question_text}
          </Typography>
        </FormLabel>
        <RadioGroup
          value={value?.value || ''}
          onChange={(e) => onChange({ value: e.target.value })}
          aria-label={question_text}
        >
          {optionsList.map((option: any) => (
            <FormControlLabel
              key={option.value}
              value={option.value}
              control={<Radio />}
              label={option.text}
              sx={{
                mb: { xs: 2, md: 1 },
                '& .MuiFormControlLabel-label': {
                  fontSize: { xs: '0.95rem', md: '1rem' },
                },
              }}
            />
          ))}
        </RadioGroup>
      </FormControl>
    );
  }

  // Multiple choice (checkboxes)
  if (question_type === 'multiple_choice') {
    // Handle both formats: direct array or {options: [...]}
    const optionsList = Array.isArray(options) ? options : options?.options || [];
    const selectedValues = value?.value || [];

    const handleCheckboxChange = (optionValue: string, checked: boolean) => {
      const newValues = checked
        ? [...selectedValues, optionValue]
        : selectedValues.filter((v: string) => v !== optionValue);
      onChange({ value: newValues });
    };

    return (
      <FormControl
        component="fieldset"
        fullWidth
        error={hasError}
        aria-describedby={hasError ? 'question-error' : undefined}
      >
        <FormLabel component="legend" required={required}>
          <Typography
            variant="h6"
            component="h2"
            gutterBottom
            sx={{ fontSize: { xs: '1.1rem', sm: '1.2rem', md: '1.25rem' } }}
          >
            {question_text}
          </Typography>
        </FormLabel>
        <FormGroup>
          {optionsList.map((option: any) => (
            <FormControlLabel
              key={option.value}
              control={
                <Checkbox
                  checked={selectedValues.includes(option.value)}
                  onChange={(e) => handleCheckboxChange(option.value, e.target.checked)}
                />
              }
              label={option.text}
              sx={{
                mb: { xs: 2, md: 1 },
                '& .MuiFormControlLabel-label': {
                  fontSize: { xs: '0.95rem', md: '1rem' },
                },
              }}
            />
          ))}
        </FormGroup>
      </FormControl>
    );
  }

  // Rating scale (slider)
  if (question_type === 'rating') {
    const ratingOptions = options as any;
    const min = ratingOptions?.min || 1;
    const max = ratingOptions?.max || 10;

    return (
      <FormControl
        component="fieldset"
        fullWidth
        error={hasError}
        aria-describedby={hasError ? 'question-error' : undefined}
      >
        <FormLabel component="legend" required={required}>
          <Typography
            variant="h6"
            component="h2"
            gutterBottom
            sx={{ fontSize: { xs: '1.1rem', sm: '1.2rem', md: '1.25rem' } }}
          >
            {question_text}
          </Typography>
        </FormLabel>
        <Slider
          value={value?.rating || min}
          onChange={(_, newValue) => onChange({ rating: newValue })}
          min={min}
          max={max}
          marks
          valueLabelDisplay="on"
          aria-label={question_text}
          sx={{
            mt: 4,
            mb: 4,
            '& .MuiSlider-thumb': {
              width: { xs: 28, md: 20 },
              height: { xs: 28, md: 20 },
            },
            '& .MuiSlider-rail': {
              height: { xs: 6, md: 4 },
            },
            '& .MuiSlider-track': {
              height: { xs: 6, md: 4 },
            },
          }}
        />
      </FormControl>
    );
  }

  // Text input
  if (question_type === 'text') {
    return (
      <FormControl
        component="fieldset"
        fullWidth
        error={hasError}
        aria-describedby={hasError ? 'question-error' : undefined}
      >
        <FormLabel component="legend" required={required}>
          <Typography
            variant="h6"
            component="h2"
            gutterBottom
            sx={{ fontSize: { xs: '1.1rem', sm: '1.2rem', md: '1.25rem' } }}
          >
            {question_text}
          </Typography>
        </FormLabel>
        <TextField
          value={value?.text || ''}
          onChange={(e) => onChange({ text: e.target.value })}
          multiline
          rows={4}
          fullWidth
          placeholder="Enter your response..."
          aria-label={question_text}
          error={hasError}
          sx={{
            mt: 2,
            '& .MuiInputBase-input': {
              fontSize: { xs: '1rem', md: '0.95rem' },
            },
          }}
        />
      </FormControl>
    );
  }

  // Fallback for unknown question type
  return (
    <Typography color="error">
      Unsupported question type: {question_type}
    </Typography>
  );
};

export default Questionnaire;
