import React, { useEffect, useState } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  CircularProgress,
  Alert,
  Paper,
  Tabs,
  Tab,
  Breadcrumbs,
  Link,
} from '@mui/material';
import { Home as HomeIcon, Assessment as AssessmentIcon } from '@mui/icons-material';
import { apiService } from '@/services/api';
import { ReportGenerationButton } from '@/components/Reports/ReportGenerationButton';
import { PDFViewer } from '@/components/Reports/PDFViewer';
import type { AssessmentDetail, Report } from '@/types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`report-tabpanel-${index}`}
      aria-labelledby={`report-tab-${index}`}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
};

export const ReportPreview: React.FC = () => {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reports, setReports] = useState<{
    consultantReport: Report;
    clientReport: Report;
  } | null>(null);
  const [tabValue, setTabValue] = useState(0);

  useEffect(() => {
    const fetchAssessment = async () => {
      if (!assessmentId) {
        setError('No assessment ID provided');
        setLoading(false);
        return;
      }

      try {
        const data = await apiService.getAssessment(assessmentId);
        setAssessment(data);
      } catch (err) {
        setError('Error loading assessment');
      } finally {
        setLoading(false);
      }
    };

    fetchAssessment();
  }, [assessmentId]);

  const handleReportSuccess = (generatedReports: {
    consultantReport: Report;
    clientReport: Report;
  }) => {
    setReports(generatedReports);
    setTabValue(0); // Switch to consultant report tab
  };

  const handleReportError = (err: Error) => {
    setError(err.message);
  };

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading assessment...</Typography>
      </Container>
    );
  }

  if (error || !assessment) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="error">
          {error || 'Error loading assessment'}
        </Alert>
      </Container>
    );
  }

  const isCompleted = assessment.status === 'completed';

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Breadcrumbs aria-label="breadcrumb" sx={{ mb: 3 }}>
        <Link
          component={RouterLink}
          to="/dashboard"
          underline="hover"
          color="inherit"
          sx={{ display: 'flex', alignItems: 'center' }}
        >
          <HomeIcon sx={{ mr: 0.5 }} fontSize="small" />
          Back to Dashboard
        </Link>
        <Typography color="text.primary" sx={{ display: 'flex', alignItems: 'center' }}>
          <AssessmentIcon sx={{ mr: 0.5 }} fontSize="small" />
          Reports
        </Typography>
      </Breadcrumbs>

      <Typography variant="h1" component="h1" gutterBottom sx={{ fontSize: '2rem', fontWeight: 'bold' }}>
        Reports for {assessment.clientName}
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Assessment Details
        </Typography>
        <Typography variant="body1" color="text.secondary">
          <strong>Business:</strong> {assessment.businessName}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          <strong>Email:</strong> {assessment.clientEmail}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          <strong>Status:</strong> {assessment.status}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          <strong>Progress:</strong> {assessment.progress}%
        </Typography>
        {assessment.completedAt && (
          <Typography variant="body1" color="text.secondary">
            <strong>Completed:</strong> {new Date(assessment.completedAt).toLocaleString()}
          </Typography>
        )}
      </Paper>

      {!isCompleted && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          This assessment is not yet completed. Please complete the assessment before generating reports.
        </Alert>
      )}

      {!reports && (
        <Box sx={{ mb: 3 }}>
          <ReportGenerationButton
            assessmentId={assessmentId!}
            onSuccess={handleReportSuccess}
            onError={handleReportError}
            disabled={!isCompleted}
          />
        </Box>
      )}

      {reports && (
        <Paper sx={{ mt: 3 }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={tabValue} onChange={handleTabChange} aria-label="report tabs">
              <Tab label="Consultant Report" id="report-tab-0" aria-controls="report-tabpanel-0" />
              <Tab label="Client Report" id="report-tab-1" aria-controls="report-tabpanel-1" />
            </Tabs>
          </Box>

          <TabPanel value={tabValue} index={0}>
            <PDFViewer
              pdfUrl={reports.consultantReport.pdfUrl}
              title="Consultant Report"
            />
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <PDFViewer
              pdfUrl={reports.clientReport.pdfUrl}
              title="Client Report"
            />
          </TabPanel>
        </Paper>
      )}
    </Container>
  );
};

export default ReportPreview;
