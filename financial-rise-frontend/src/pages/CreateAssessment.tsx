import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Box,
  Button,
  Card,
  CardContent,
  TextField,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import { Save as SaveIcon, Cancel as CancelIcon } from '@mui/icons-material';
import { AppLayout } from '@/components/Layout/AppLayout';
import { apiService } from '@/services/api';
import { useAssessmentStore } from '@/store/assessmentStore';

/**
 * Validation schema for assessment creation
 * REQ-ASSESS-001: Required fields validation
 */
const assessmentSchema = z.object({
  clientName: z.string().min(1, 'Client name is required').max(100, 'Client name must be 100 characters or less'),
  businessName: z.string().min(1, 'Business name is required').max(100, 'Business name must be 100 characters or less'),
  clientEmail: z.string().email('Invalid email address').max(255, 'Email must be 255 characters or less'),
  notes: z.string().max(1000, 'Notes must be 1000 characters or less').optional(),
});

type AssessmentFormData = z.infer<typeof assessmentSchema>;

/**
 * Create Assessment Page
 * REQ-ASSESS-001: Create new assessment with required fields
 * REQ-UI-007: Inline form validation
 */
export const CreateAssessment: React.FC = () => {
  const navigate = useNavigate();
  const { addAssessment } = useAssessmentStore();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<AssessmentFormData>({
    resolver: zodResolver(assessmentSchema),
    mode: 'onBlur',
  });

  const onSubmit = async (data: AssessmentFormData) => {
    try {
      setSubmitting(true);
      setError(null);

      const assessment = await apiService.createAssessment(data);
      addAssessment(assessment);

      // Navigate to the questionnaire
      navigate(`/assessment/${assessment.assessmentId}`);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to create assessment');
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    navigate('/dashboard');
  };

  return (
    <AppLayout>
      <Box sx={{ maxWidth: 800, mx: 'auto' }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Create New Assessment
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph>
          Enter the client information to begin a new financial readiness assessment.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        <Card>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {/* Client Name */}
                <TextField
                  label="Client Name"
                  fullWidth
                  required
                  {...register('clientName')}
                  error={!!errors.clientName}
                  helperText={errors.clientName?.message}
                  disabled={submitting}
                  inputProps={{
                    'aria-label': 'Client name',
                    'aria-required': 'true',
                  }}
                />

                {/* Business Name */}
                <TextField
                  label="Business Name"
                  fullWidth
                  required
                  {...register('businessName')}
                  error={!!errors.businessName}
                  helperText={errors.businessName?.message}
                  disabled={submitting}
                  inputProps={{
                    'aria-label': 'Business name',
                    'aria-required': 'true',
                  }}
                />

                {/* Client Email */}
                <TextField
                  label="Client Email"
                  type="email"
                  fullWidth
                  required
                  {...register('clientEmail')}
                  error={!!errors.clientEmail}
                  helperText={errors.clientEmail?.message}
                  disabled={submitting}
                  inputProps={{
                    'aria-label': 'Client email address',
                    'aria-required': 'true',
                  }}
                />

                {/* Notes (Optional) */}
                <TextField
                  label="Notes (Optional)"
                  multiline
                  rows={4}
                  fullWidth
                  {...register('notes')}
                  error={!!errors.notes}
                  helperText={errors.notes?.message || 'Additional notes about this assessment'}
                  disabled={submitting}
                  inputProps={{
                    'aria-label': 'Additional notes',
                    maxLength: 1000,
                  }}
                />

                {/* Action Buttons */}
                <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end', mt: 2 }}>
                  <Button
                    variant="outlined"
                    startIcon={<CancelIcon />}
                    onClick={handleCancel}
                    disabled={submitting}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    variant="contained"
                    startIcon={submitting ? <CircularProgress size={20} /> : <SaveIcon />}
                    disabled={submitting}
                  >
                    {submitting ? 'Creating...' : 'Create Assessment'}
                  </Button>
                </Box>
              </Box>
            </form>
          </CardContent>
        </Card>
      </Box>
    </AppLayout>
  );
};

export default CreateAssessment;
