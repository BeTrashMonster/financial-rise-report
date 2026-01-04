/**
 * Create Assessment Form
 * Work Stream 2: Create Assessment Form
 *
 * Features:
 * - Mobile-responsive form layout
 * - Accessible form with proper labels and error announcements
 * - Inline validation with React Hook Form
 * - Confirmation dialog before canceling if form is dirty
 * - WCAG 2.1 AA accessibility compliance
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm, Controller } from 'react-hook-form';
import {
  Box,
  Container,
  Typography,
  TextField,
  Button,
  Paper,
  Alert,
  Grid,
} from '@mui/material';
import { Save as SaveIcon, Cancel as CancelIcon } from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { createAssessment } from '@store/slices/assessmentSlice';
import { Modal } from '@components/common/Modal/Modal';
import type { CreateAssessmentRequest } from '@services/assessmentService';

interface FormData extends CreateAssessmentRequest {
  clientName: string;
  businessName: string;
  clientEmail: string;
  notes?: string;
}

/**
 * Create Assessment Form Component
 */
export const CreateAssessment: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { loading, error } = useAppSelector((state) => state.assessment);

  const [showCancelDialog, setShowCancelDialog] = useState(false);

  // React Hook Form setup with validation
  const {
    control,
    handleSubmit,
    formState: { errors, isDirty },
  } = useForm<FormData>({
    mode: 'onBlur',
    defaultValues: {
      clientName: '',
      businessName: '',
      clientEmail: '',
      notes: '',
    },
  });

  // Handle form submission
  const onSubmit = async (data: FormData) => {
    try {
      const result = await dispatch(createAssessment(data)).unwrap();

      // Navigate to questionnaire page with the new assessment ID
      navigate(`/assessments/${result.id}/questionnaire`);
    } catch (err) {
      // Error is handled by Redux and displayed in error state
      console.error('Failed to create assessment:', err);
    }
  };

  // Handle cancel button click
  const handleCancel = () => {
    if (isDirty) {
      // Show confirmation dialog if form has unsaved changes
      setShowCancelDialog(true);
    } else {
      // Navigate back if no changes
      navigate('/assessments');
    }
  };

  // Confirm cancel and navigate back
  const handleConfirmCancel = () => {
    setShowCancelDialog(false);
    navigate('/assessments');
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Create New Assessment
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Enter client information to begin a new financial readiness assessment
        </Typography>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Form */}
      <Paper sx={{ p: { xs: 2, sm: 3, md: 4 } }}>
        <form onSubmit={handleSubmit(onSubmit)} noValidate>
          <Grid container spacing={3}>
            {/* Client Name */}
            <Grid item xs={12}>
              <Controller
                name="clientName"
                control={control}
                rules={{
                  required: 'Client name is required',
                  maxLength: {
                    value: 100,
                    message: 'Client name must be 100 characters or less',
                  },
                  pattern: {
                    value: /^[a-zA-Z\s'-]+$/,
                    message: 'Client name can only contain letters, spaces, hyphens, and apostrophes',
                  },
                }}
                render={({ field }) => (
                  <TextField
                    {...field}
                    id="clientName"
                    label="Client Name"
                    fullWidth
                    required
                    error={!!errors.clientName}
                    helperText={errors.clientName?.message}
                    placeholder="John Smith"
                    autoComplete="name"
                    autoFocus
                    inputProps={{
                      maxLength: 100,
                      'aria-required': 'true',
                      'aria-invalid': !!errors.clientName ? 'true' : 'false',
                      'aria-describedby': errors.clientName
                        ? 'clientName-error'
                        : undefined,
                    }}
                    FormHelperTextProps={{
                      id: errors.clientName ? 'clientName-error' : undefined,
                      role: errors.clientName ? 'alert' : undefined,
                    }}
                  />
                )}
              />
            </Grid>

            {/* Business Name */}
            <Grid item xs={12}>
              <Controller
                name="businessName"
                control={control}
                rules={{
                  required: 'Business name is required',
                  maxLength: {
                    value: 100,
                    message: 'Business name must be 100 characters or less',
                  },
                }}
                render={({ field }) => (
                  <TextField
                    {...field}
                    id="businessName"
                    label="Business Name"
                    fullWidth
                    required
                    error={!!errors.businessName}
                    helperText={errors.businessName?.message}
                    placeholder="Acme Corporation"
                    autoComplete="organization"
                    inputProps={{
                      maxLength: 100,
                      'aria-required': 'true',
                      'aria-invalid': !!errors.businessName ? 'true' : 'false',
                      'aria-describedby': errors.businessName
                        ? 'businessName-error'
                        : undefined,
                    }}
                    FormHelperTextProps={{
                      id: errors.businessName ? 'businessName-error' : undefined,
                      role: errors.businessName ? 'alert' : undefined,
                    }}
                  />
                )}
              />
            </Grid>

            {/* Client Email */}
            <Grid item xs={12}>
              <Controller
                name="clientEmail"
                control={control}
                rules={{
                  required: 'Email address is required',
                  maxLength: {
                    value: 255,
                    message: 'Email must be 255 characters or less',
                  },
                  pattern: {
                    value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                    message: 'Please enter a valid email address',
                  },
                }}
                render={({ field }) => (
                  <TextField
                    {...field}
                    id="clientEmail"
                    label="Client Email"
                    type="email"
                    fullWidth
                    required
                    error={!!errors.clientEmail}
                    helperText={errors.clientEmail?.message}
                    placeholder="john.smith@example.com"
                    autoComplete="email"
                    inputProps={{
                      maxLength: 255,
                      'aria-required': 'true',
                      'aria-invalid': !!errors.clientEmail ? 'true' : 'false',
                      'aria-describedby': errors.clientEmail
                        ? 'clientEmail-error'
                        : undefined,
                    }}
                    FormHelperTextProps={{
                      id: errors.clientEmail ? 'clientEmail-error' : undefined,
                      role: errors.clientEmail ? 'alert' : undefined,
                    }}
                  />
                )}
              />
            </Grid>

            {/* Notes (Optional) */}
            <Grid item xs={12}>
              <Controller
                name="notes"
                control={control}
                rules={{
                  maxLength: {
                    value: 5000,
                    message: 'Notes must be 5000 characters or less',
                  },
                }}
                render={({ field }) => (
                  <TextField
                    {...field}
                    id="notes"
                    label="Notes (Optional)"
                    fullWidth
                    multiline
                    rows={4}
                    error={!!errors.notes}
                    helperText={
                      errors.notes?.message ||
                      `${field.value?.length || 0}/5000 characters`
                    }
                    placeholder="Add any notes about this assessment..."
                    inputProps={{
                      maxLength: 5000,
                      'aria-invalid': !!errors.notes ? 'true' : 'false',
                      'aria-describedby': errors.notes ? 'notes-error' : 'notes-helper',
                    }}
                    FormHelperTextProps={{
                      id: errors.notes ? 'notes-error' : 'notes-helper',
                      role: errors.notes ? 'alert' : undefined,
                    }}
                  />
                )}
              />
            </Grid>

            {/* Form Actions */}
            <Grid item xs={12}>
              <Box
                sx={{
                  display: 'flex',
                  gap: 2,
                  flexDirection: { xs: 'column', sm: 'row' },
                  justifyContent: 'flex-end',
                }}
              >
                <Button
                  variant="outlined"
                  onClick={handleCancel}
                  disabled={loading}
                  startIcon={<CancelIcon />}
                  aria-label="Cancel and return to assessment list"
                  sx={{ order: { xs: 2, sm: 1 } }}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="contained"
                  disabled={loading}
                  startIcon={<SaveIcon />}
                  aria-label="Create assessment and continue"
                  sx={{ order: { xs: 1, sm: 2 } }}
                >
                  {loading ? 'Creating...' : 'Create Assessment'}
                </Button>
              </Box>
            </Grid>
          </Grid>
        </form>
      </Paper>

      {/* Cancel Confirmation Dialog */}
      <Modal
        open={showCancelDialog}
        onClose={() => setShowCancelDialog(false)}
        title="Discard Changes?"
        maxWidth="xs"
        actions={
          <>
            <Button
              variant="outlined"
              onClick={() => setShowCancelDialog(false)}
              aria-label="Continue editing"
            >
              Continue Editing
            </Button>
            <Button
              variant="contained"
              color="error"
              onClick={handleConfirmCancel}
              aria-label="Discard changes and return to list"
            >
              Discard Changes
            </Button>
          </>
        }
      >
        <Typography variant="body1">
          You have unsaved changes. Are you sure you want to discard them and return to
          the assessment list?
        </Typography>
      </Modal>
    </Container>
  );
};

export default CreateAssessment;
