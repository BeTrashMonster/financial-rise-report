import React, { useState } from 'react';
import {
  Button,
  Box,
  Typography,
  Alert,
  Link,
  CircularProgress,
  Stack,
} from '@mui/material';
import { apiService } from '@/services/api';
import type { Report } from '@/types';

export interface ReportGenerationButtonProps {
  assessmentId: string;
  onSuccess?: (reports: { consultantReport: Report; clientReport: Report }) => void;
  onError?: (error: Error) => void;
  disabled?: boolean;
}

export const ReportGenerationButton: React.FC<ReportGenerationButtonProps> = ({
  assessmentId,
  onSuccess,
  onError,
  disabled = false,
}) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [reports, setReports] = useState<{
    consultantReport: Report;
    clientReport: Report;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateReports = async () => {
    setIsGenerating(true);
    setError(null);

    try {
      const response = await apiService.generateBothReports(assessmentId);
      setReports(response.data);
      onSuccess?.(response.data);
    } catch (err) {
      const error = err as Error;
      setError(error.message || 'Failed to generate reports');
      onError?.(error);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <Box>
      {!reports && (
        <Button
          variant="contained"
          color="primary"
          onClick={handleGenerateReports}
          disabled={disabled || isGenerating}
          aria-label="Generate reports"
          startIcon={isGenerating ? <CircularProgress size={20} color="inherit" /> : null}
        >
          {isGenerating ? 'Generating...' : 'Generate Reports'}
        </Button>
      )}

      {reports && (
        <Stack spacing={2}>
          <Alert severity="success">Reports generated successfully!</Alert>

          <Box>
            <Typography variant="h6" gutterBottom>
              Download Reports
            </Typography>
            <Stack spacing={1}>
              <Link
                href={reports.consultantReport.pdfUrl}
                target="_blank"
                rel="noopener noreferrer"
                download
              >
                Download Consultant Report
              </Link>
              <Link
                href={reports.clientReport.pdfUrl}
                target="_blank"
                rel="noopener noreferrer"
                download
              >
                Download Client Report
              </Link>
            </Stack>
          </Box>

          <Button
            variant="outlined"
            color="primary"
            onClick={handleGenerateReports}
            disabled={isGenerating}
            aria-label="Regenerate reports"
          >
            Regenerate Reports
          </Button>
        </Stack>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }}>
          Failed to generate reports: {error}
        </Alert>
      )}
    </Box>
  );
};
