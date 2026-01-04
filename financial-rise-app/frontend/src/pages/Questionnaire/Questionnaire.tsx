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
 */
const getSectionColor = (section: string): string => {
  const colors: Record<string, string> = {
    stabilize: '#D32F2F',
    organize: '#ED6C02',
    build: '#FBC02D',
    grow: '#388E3C',
    systemic: '#0288D1',
    disc: '#7B2FA1',
    metadata: '#616161',
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

  const [autoSaveStatus, setAutoSaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');
  const autoSaveTimerRef = useRef<NodeJS.Timeout | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

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

  // Auto-save function
  const handleAutoSave = async () => {
    if (!assessmentId) return;

    setAutoSaveStatus('saving');
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

      setAutoSaveStatus('saved');
      setTimeout(() => setAutoSaveStatus('idle'), 2000);
    } catch (err) {
      console.error('Auto-save failed:', err);
      setAutoSaveStatus('idle');
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
    if (!assessmentId) return;

    setState((prev) => ({ ...prev, afterConfidence: value, isCalculating: true }));

    try {
      // Submit final auto-save
      await handleAutoSave();

      // Calculate results
      await assessmentService.submitAssessment(assessmentId);

      // Navigate to results page
      navigate(`/assessments/${assessmentId}/results`);
    } catch (err: any) {
      setFormError(err.response?.data?.message || 'Failed to submit assessment');
      setState((prev) => ({ ...prev, isCalculating: false }));
    }
  };

  // Navigation handlers
  const handleNext = () => {
    const currentQuestion = questions[state.currentQuestionIndex];

    // Validate required question
    if (currentQuestion?.required && !state.responses.has(currentQuestion.question_key)) {
      setFormError('Please answer this question before continuing');
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
    await handleAutoSave();
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

  // Loading state
  if (loading && questions.length === 0) {
    return (
      <Container maxWidth="md" sx={{ py: 8, textAlign: 'center' }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 3 }}>
          Loading questionnaire...
        </Typography>
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
            To help us measure the value of this assessment, please rate your current confidence in understanding your business's financial readiness.
          </Typography>

          <Box sx={{ mt: 4, mb: 2 }}>
            <FormControl component="fieldset" fullWidth>
              <FormLabel component="legend" sx={{ mb: 3 }}>
                <Typography variant="h6">
                  How confident are you in your understanding of your business's financial health?
                </Typography>
              </FormLabel>

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

  // Main questionnaire view
  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      {/* Header with progress */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h5" component="h1">
            Financial Readiness Assessment
          </Typography>

          {/* Auto-save indicator */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {autoSaveStatus === 'saving' && (
              <>
                <CircularProgress size={16} />
                <Typography variant="caption" color="text.secondary">
                  Saving...
                </Typography>
              </>
            )}
            {autoSaveStatus === 'saved' && (
              <>
                <CheckCircleIcon fontSize="small" color="success" />
                <Typography variant="caption" color="success.main">
                  Saved
                </Typography>
              </>
            )}
          </Box>
        </Box>

        {/* Progress bar */}
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Question {state.currentQuestionIndex + 1} of {totalQuestions}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {answeredCount} answered
            </Typography>
          </Box>
          <LinearProgress variant="determinate" value={progress} sx={{ height: 8, borderRadius: 4 }} />
        </Box>

        {/* Section breadcrumb */}
        <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} aria-label="section navigation">
          <Chip
            label={getSectionName(currentSection)}
            size="small"
            sx={{
              backgroundColor: getSectionColor(currentSection),
              color: 'white',
              fontWeight: 600,
            }}
          />
        </Breadcrumbs>
      </Box>

      {/* Error alert */}
      {formError && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setFormError(null)}>
          {formError}
        </Alert>
      )}

      {/* Question content */}
      {currentQuestion && (
        <Paper sx={{ p: { xs: 3, md: 4 } }}>
          <QuestionRenderer
            question={currentQuestion}
            value={state.responses.get(currentQuestion.question_key)?.answer}
            onChange={(answer) => handleAnswerChange(currentQuestion, answer)}
          />

          <Divider sx={{ my: 4 }} />

          {/* Navigation buttons */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Button
                variant="outlined"
                onClick={handlePrevious}
                disabled={state.currentQuestionIndex === 0}
                startIcon={<NavigateBeforeIcon />}
              >
                Previous
              </Button>
              <Button
                variant="outlined"
                onClick={handleSaveAndExit}
                startIcon={<ExitIcon />}
                disabled={autoSaveStatus === 'saving'}
              >
                Save & Exit
              </Button>
            </Box>

            <Button
              variant="contained"
              onClick={handleNext}
              endIcon={<NavigateNextIcon />}
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
 * Question Renderer Component
 * Renders different question types dynamically
 */
interface QuestionRendererProps {
  question: Question;
  value: any;
  onChange: (value: any) => void;
}

const QuestionRenderer: React.FC<QuestionRendererProps> = ({ question, value, onChange }) => {
  const { question_text, question_type, options, required } = question;

  // Single choice (radio buttons)
  if (question_type === 'single_choice' && Array.isArray(options)) {
    return (
      <FormControl component="fieldset" fullWidth>
        <FormLabel component="legend" required={required}>
          <Typography variant="h6" component="h2" gutterBottom>
            {question_text}
          </Typography>
        </FormLabel>
        <RadioGroup
          value={value?.value || ''}
          onChange={(e) => onChange({ value: e.target.value })}
          aria-label={question_text}
        >
          {options.map((option: any) => (
            <FormControlLabel
              key={option.value}
              value={option.value}
              control={<Radio />}
              label={option.label}
            />
          ))}
        </RadioGroup>
      </FormControl>
    );
  }

  // Multiple choice (checkboxes)
  if (question_type === 'multiple_choice' && Array.isArray(options)) {
    const selectedValues = value?.values || [];

    const handleCheckboxChange = (optionValue: string, checked: boolean) => {
      const newValues = checked
        ? [...selectedValues, optionValue]
        : selectedValues.filter((v: string) => v !== optionValue);
      onChange({ values: newValues });
    };

    return (
      <FormControl component="fieldset" fullWidth>
        <FormLabel component="legend" required={required}>
          <Typography variant="h6" component="h2" gutterBottom>
            {question_text}
          </Typography>
        </FormLabel>
        <FormGroup>
          {options.map((option: any) => (
            <FormControlLabel
              key={option.value}
              control={
                <Checkbox
                  checked={selectedValues.includes(option.value)}
                  onChange={(e) => handleCheckboxChange(option.value, e.target.checked)}
                />
              }
              label={option.label}
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
      <FormControl component="fieldset" fullWidth>
        <FormLabel component="legend" required={required}>
          <Typography variant="h6" component="h2" gutterBottom>
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
          sx={{ mt: 4, mb: 4 }}
        />
      </FormControl>
    );
  }

  // Text input
  if (question_type === 'text') {
    return (
      <FormControl component="fieldset" fullWidth>
        <FormLabel component="legend" required={required}>
          <Typography variant="h6" component="h2" gutterBottom>
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
          sx={{ mt: 2 }}
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
