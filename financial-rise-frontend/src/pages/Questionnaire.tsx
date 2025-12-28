import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  FormControlLabel,
  Checkbox,
  TextField,
  Alert,
  CircularProgress,
  Chip,
} from '@mui/material';
import {
  NavigateBefore as PrevIcon,
  NavigateNext as NextIcon,
  CheckCircle as CompleteIcon,
} from '@mui/icons-material';
import { AppLayout } from '@/components/Layout/AppLayout';
import { ProgressIndicator } from '@/components/Assessment/ProgressIndicator';
import { AutoSaveIndicator } from '@/components/Assessment/AutoSaveIndicator';
import { SingleChoiceQuestion } from '@/components/Questions/SingleChoiceQuestion';
import { MultipleChoiceQuestion } from '@/components/Questions/MultipleChoiceQuestion';
import { RatingQuestion } from '@/components/Questions/RatingQuestion';
import { TextQuestion } from '@/components/Questions/TextQuestion';
import { useAssessmentStore } from '@/store/assessmentStore';
import { useAutoSave } from '@/hooks/useAutoSave';
import { apiClient } from '@/services/apiClient';
import type { Question, QuestionType, Questionnaire as QuestionnaireType } from '@/types';

/**
 * Questionnaire Page
 * Main assessment questionnaire workflow
 * REQ-ASSESS-007: Mark questions as N/A
 * REQ-ASSESS-008: Forward/backward navigation
 */
export const Questionnaire: React.FC = () => {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const navigate = useNavigate();

  const {
    currentAssessment,
    setCurrentAssessment,
    currentQuestionIndex,
    setCurrentQuestionIndex,
    responses,
    setResponse,
    setResponses,
    isDirty,
    lastSavedAt,
    reset,
  } = useAssessmentStore();

  const [questionnaire, setQuestionnaire] = useState<QuestionnaireType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [completing, setCompleting] = useState(false);

  // Auto-save hook
  const { saveNow, isSaving } = useAutoSave(assessmentId || null, true);

  // Get all questions flattened
  const allQuestions = questionnaire?.sections.flatMap((s) => s.questions) || [];
  const currentQuestion = allQuestions[currentQuestionIndex];

  // Get current response
  const currentResponse = currentQuestion ? responses.get(currentQuestion.questionId) : null;

  useEffect(() => {
    if (assessmentId) {
      loadAssessmentAndQuestionnaire();
    }
    return () => reset();
  }, [assessmentId]);

  const loadAssessmentAndQuestionnaire = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load assessment and questionnaire in parallel
      const [assessment, questionnaireData] = await Promise.all([
        apiClient.getAssessment(assessmentId!),
        apiClient.getQuestionnaire(),
      ]);

      setCurrentAssessment(assessment);
      setQuestionnaire(questionnaireData);
      setResponses(assessment.responses);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to load assessment');
    } finally {
      setLoading(false);
    }
  };

  const handleAnswerChange = (value: any) => {
    if (!currentQuestion) return;

    setResponse(currentQuestion.questionId, {
      questionId: currentQuestion.questionId,
      answer: value,
      notApplicable: false,
      consultantNotes: currentResponse?.consultantNotes,
    });
  };

  const handleNotApplicableChange = (checked: boolean) => {
    if (!currentQuestion) return;

    setResponse(currentQuestion.questionId, {
      questionId: currentQuestion.questionId,
      answer: checked ? null : currentResponse?.answer,
      notApplicable: checked,
      consultantNotes: currentResponse?.consultantNotes,
    });
  };

  const handleNotesChange = (notes: string) => {
    if (!currentQuestion) return;

    setResponse(currentQuestion.questionId, {
      questionId: currentQuestion.questionId,
      answer: currentResponse?.answer,
      notApplicable: currentResponse?.notApplicable || false,
      consultantNotes: notes,
    });
  };

  const handlePrevious = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex(currentQuestionIndex - 1);
    }
  };

  const handleNext = () => {
    if (currentQuestionIndex < allQuestions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
    }
  };

  const handleComplete = async () => {
    if (!assessmentId) return;

    try {
      setCompleting(true);

      // Save any pending changes first
      if (isDirty) {
        await saveNow();
      }

      // Mark assessment as completed
      await apiClient.updateAssessment(assessmentId, {
        status: 'completed',
      });

      // Navigate to dashboard
      navigate('/dashboard');
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to complete assessment');
      setCompleting(false);
    }
  };

  const renderQuestion = () => {
    if (!currentQuestion) return null;

    const isDisabled = currentResponse?.notApplicable || false;
    const value = currentResponse?.answer;

    switch (currentQuestion.type) {
      case 'single_choice':
        return (
          <SingleChoiceQuestion
            question={currentQuestion}
            value={value}
            onChange={handleAnswerChange}
            disabled={isDisabled}
          />
        );

      case 'multiple_choice':
        return (
          <MultipleChoiceQuestion
            question={currentQuestion}
            value={value}
            onChange={handleAnswerChange}
            disabled={isDisabled}
          />
        );

      case 'rating':
        return (
          <RatingQuestion
            question={currentQuestion}
            value={value}
            onChange={handleAnswerChange}
            disabled={isDisabled}
          />
        );

      case 'text':
        return (
          <TextQuestion
            question={currentQuestion}
            value={value}
            onChange={handleAnswerChange}
            disabled={isDisabled}
          />
        );

      default:
        return <Typography>Unsupported question type</Typography>;
    }
  };

  if (loading) {
    return (
      <AppLayout>
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '50vh' }}>
          <CircularProgress />
        </Box>
      </AppLayout>
    );
  }

  if (error || !currentAssessment || !questionnaire) {
    return (
      <AppLayout>
        <Alert severity="error">{error || 'Failed to load assessment'}</Alert>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <Box sx={{ maxWidth: 900, mx: 'auto' }}>
        {/* Header */}
        <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h5" gutterBottom>
              {currentAssessment.businessName}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {currentAssessment.clientName}
            </Typography>
          </Box>
          <AutoSaveIndicator
            isSaving={isSaving}
            isDirty={isDirty}
            lastSavedAt={lastSavedAt}
          />
        </Box>

        {/* Progress */}
        <Box sx={{ mb: 4 }}>
          <ProgressIndicator progress={currentAssessment.progress} />
        </Box>

        {/* Current Section Info */}
        {currentQuestion && (
          <Box sx={{ mb: 2 }}>
            <Chip
              label={`Question ${currentQuestionIndex + 1} of ${allQuestions.length}`}
              color="primary"
              variant="outlined"
            />
          </Box>
        )}

        {/* Question Card */}
        <Card sx={{ mb: 3 }}>
          <CardContent sx={{ p: 4 }}>
            {renderQuestion()}

            {/* Not Applicable Checkbox */}
            <Box sx={{ mt: 3, pt: 3, borderTop: '1px solid', borderColor: 'divider' }}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={currentResponse?.notApplicable || false}
                    onChange={(e) => handleNotApplicableChange(e.target.checked)}
                  />
                }
                label="Mark as Not Applicable"
              />
            </Box>

            {/* Consultant Notes */}
            <Box sx={{ mt: 3 }}>
              <TextField
                label="Consultant Notes (Optional)"
                multiline
                rows={3}
                fullWidth
                value={currentResponse?.consultantNotes || ''}
                onChange={(e) => handleNotesChange(e.target.value)}
                placeholder="Add private notes about this question..."
                inputProps={{
                  maxLength: 1000,
                  'aria-label': 'Consultant notes',
                }}
              />
            </Box>
          </CardContent>
        </Card>

        {/* Navigation */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<PrevIcon />}
            onClick={handlePrevious}
            disabled={currentQuestionIndex === 0}
          >
            Previous
          </Button>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {currentQuestionIndex === allQuestions.length - 1 ? (
              <Button
                variant="contained"
                color="success"
                startIcon={completing ? <CircularProgress size={20} /> : <CompleteIcon />}
                onClick={handleComplete}
                disabled={completing}
              >
                {completing ? 'Completing...' : 'Complete Assessment'}
              </Button>
            ) : (
              <Button
                variant="contained"
                endIcon={<NextIcon />}
                onClick={handleNext}
              >
                Next
              </Button>
            )}
          </Box>
        </Box>
      </Box>
    </AppLayout>
  );
};

export default Questionnaire;
