/**
 * Results Display Page
 * Work Stream 4: Results Display Page
 *
 * Features:
 * - DISC personality profile display with bar charts (REQ-DISC-004)
 * - Phase results with visual roadmap (REQ-PHASE-003, REQ-REPORT-CL-003)
 * - Before/after confidence comparison (REQ-QUEST-009)
 * - Communication strategies for consultant (REQ-REPORT-C-003)
 * - Alt text for all charts (REQ-ACCESS-002)
 * - Data table alternative for screen readers
 * - Mobile-responsive, accessible design (WCAG 2.1 AA)
 */

import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Grid,
  LinearProgress,
  Chip,
  Alert,
  CircularProgress,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  ArrowForward as ArrowForwardIcon,
  TrendingUp as TrendingUpIcon,
  Article as ArticleIcon,
} from '@mui/icons-material';
import { assessmentService } from '@services/assessmentService';
import type { DISCProfileWithSummary, PhaseResultsWithDetails, DISCType, FinancialPhase } from '@/types/results';
import type { Assessment } from '@store/slices/assessmentSlice';
import type { ReportStatus, ReportType } from '@/types/reports';

/**
 * Get DISC type full name
 */
const getDISCName = (type: DISCType): string => {
  const names: Record<DISCType, string> = {
    D: 'Dominance',
    I: 'Influence',
    S: 'Steadiness',
    C: 'Compliance',
  };
  return names[type];
};

/**
 * Get DISC type color
 */
const getDISCColor = (type: DISCType): string => {
  const colors: Record<DISCType, string> = {
    D: '#D32F2F', // Red
    I: '#FBC02D', // Yellow
    S: '#388E3C', // Green
    C: '#0288D1', // Blue
  };
  return colors[type];
};

/**
 * Get phase color
 */
const getPhaseColor = (phase: FinancialPhase): string => {
  const colors: Record<FinancialPhase, string> = {
    stabilize: '#D32F2F',
    organize: '#ED6C02',
    build: '#FBC02D',
    grow: '#388E3C',
    systemic: '#0288D1',
  };
  return colors[phase];
};

/**
 * Get phase display name
 */
const getPhaseName = (phase: string): string => {
  const names: Record<string, string> = {
    stabilize: 'Stabilize',
    organize: 'Organize',
    build: 'Build',
    grow: 'Grow',
    systemic: 'Financial Literacy',
  };
  return names[phase] || phase;
};

/**
 * Main Results Component
 */
export const Results: React.FC = () => {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const navigate = useNavigate();

  const [discProfile, setDiscProfile] = useState<DISCProfileWithSummary | null>(null);
  const [phaseResults, setPhaseResults] = useState<PhaseResultsWithDetails | null>(null);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Report generation state
  const [consultantReportId, setConsultantReportId] = useState<string | null>(null);
  const [clientReportId, setClientReportId] = useState<string | null>(null);
  const [consultantReportStatus, setConsultantReportStatus] = useState<ReportStatus | null>(null);
  const [clientReportStatus, setClientReportStatus] = useState<ReportStatus | null>(null);
  const [consultantReportUrl, setConsultantReportUrl] = useState<string | null>(null);
  const [clientReportUrl, setClientReportUrl] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [generatingReports, setGeneratingReports] = useState(false);
  const [pollingConsultant, setPollingConsultant] = useState(false);
  const [pollingClient, setPollingClient] = useState(false);

  // Fetch results on mount
  useEffect(() => {
    const fetchResults = async () => {
      if (!assessmentId) return;

      try {
        setLoading(true);
        setError(null);

        const [disc, phase, assess] = await Promise.all([
          assessmentService.getDISCProfile(assessmentId),
          assessmentService.getPhaseResults(assessmentId),
          assessmentService.getAssessment(assessmentId),
        ]);

        setDiscProfile(disc);
        setPhaseResults(phase);
        setAssessment(assess);
      } catch (err: any) {
        setError(err.response?.data?.message || 'Failed to load results');
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [assessmentId]);

  // Poll report status
  const pollReportStatus = async (reportId: string, reportType: ReportType) => {
    const maxAttempts = 60; // Poll for up to 60 seconds (60 attempts * 1s)
    let attempts = 0;

    const setStatus = reportType === 'consultant' ? setConsultantReportStatus : setClientReportStatus;
    const setUrl = reportType === 'consultant' ? setConsultantReportUrl : setClientReportUrl;
    const setPolling = reportType === 'consultant' ? setPollingConsultant : setPollingClient;

    setPolling(true);

    const poll = async (): Promise<void> => {
      try {
        const status = await assessmentService.getReportStatus(reportId);
        setStatus(status.status);

        if (status.status === 'completed' && status.fileUrl) {
          setUrl(status.fileUrl);
          setPolling(false);
          return;
        }

        if (status.status === 'failed') {
          setReportError(status.error || `${reportType} report generation failed`);
          setPolling(false);
          return;
        }

        attempts++;
        if (attempts >= maxAttempts) {
          setReportError(`${reportType} report generation timed out after 60 seconds`);
          setPolling(false);
          return;
        }

        // Continue polling every 1 second
        setTimeout(poll, 1000);
      } catch (err: any) {
        setReportError(err.response?.data?.message || `Failed to check ${reportType} report status`);
        setPolling(false);
      }
    };

    poll();
  };

  // Handle report generation
  const handleGenerateReports = async () => {
    if (!assessmentId) return;

    try {
      setGeneratingReports(true);
      setReportError(null);
      setConsultantReportStatus('generating');
      setClientReportStatus('generating');

      // Generate both reports in parallel
      const [consultantResponse, clientResponse] = await Promise.all([
        assessmentService.generateConsultantReport(assessmentId),
        assessmentService.generateClientReport(assessmentId),
      ]);

      setConsultantReportId(consultantResponse.reportId);
      setClientReportId(clientResponse.reportId);

      // Start polling for both reports
      pollReportStatus(consultantResponse.reportId, 'consultant');
      pollReportStatus(clientResponse.reportId, 'client');
    } catch (err: any) {
      setReportError(err.response?.data?.message || 'Failed to start report generation');
      setGeneratingReports(false);
      setConsultantReportStatus(null);
      setClientReportStatus(null);
    }
  };

  // Handle download
  const handleDownload = (url: string, filename: string) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
  };

  // Check if all reports are done (completed or failed)
  const allReportsDone =
    (consultantReportStatus === 'completed' || consultantReportStatus === 'failed') &&
    (clientReportStatus === 'completed' || clientReportStatus === 'failed');

  // Update generatingReports flag
  useEffect(() => {
    if (allReportsDone && generatingReports) {
      setGeneratingReports(false);
    }
  }, [allReportsDone, generatingReports]);

  // Loading state
  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ py: 8, textAlign: 'center' }}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 3 }}>
          Loading results...
        </Typography>
      </Container>
    );
  }

  // Error state
  if (error || !discProfile || !phaseResults) {
    return (
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error || 'Results not available'}
        </Alert>
        <Button variant="contained" onClick={() => navigate('/assessments')}>
          Return to Assessments
        </Button>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Assessment Results
        </Typography>
        <Typography variant="body1" color="text.secondary">
          {assessment?.clientName && `Client: ${assessment.clientName}`}
        </Typography>
      </Box>

      {/* Before/After Confidence Comparison */}
      {assessment?.beforeConfidence !== undefined && assessment?.afterConfidence !== undefined && (
        <Paper sx={{ p: 3, mb: 4, bgcolor: 'success.light', color: 'success.contrastText' }}>
          <Grid container spacing={3} alignItems="center">
            <Grid item xs={12} md={4}>
              <Typography variant="h6" gutterBottom>
                Before Assessment
              </Typography>
              <Typography variant="h3">{assessment.beforeConfidence}/10</Typography>
            </Grid>
            <Grid item xs={12} md={4} sx={{ textAlign: 'center' }}>
              <TrendingUpIcon sx={{ fontSize: 48 }} />
              <Typography variant="h6">
                +{assessment.afterConfidence - assessment.beforeConfidence} points
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="h6" gutterBottom>
                After Assessment
              </Typography>
              <Typography variant="h3">{assessment.afterConfidence}/10</Typography>
            </Grid>
          </Grid>
        </Paper>
      )}

      <Grid container spacing={4}>
        {/* DISC Profile Section */}
        <Grid item xs={12} lg={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h5" component="h2" gutterBottom>
              Personality Profile (DISC)
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Understanding communication preferences for effective engagement
            </Typography>

            <Divider sx={{ my: 2 }} />

            {/* Primary DISC Type */}
            <Box sx={{ mb: 3 }}>
              <Chip
                label={`Primary: ${getDISCName(discProfile.primary_type)}`}
                sx={{
                  backgroundColor: getDISCColor(discProfile.primary_type),
                  color: 'white',
                  fontWeight: 600,
                  fontSize: '1rem',
                  py: 2,
                  px: 1,
                }}
              />
              {discProfile.secondary_type && (
                <Chip
                  label={`Secondary: ${getDISCName(discProfile.secondary_type)}`}
                  sx={{
                    ml: 1,
                    backgroundColor: getDISCColor(discProfile.secondary_type),
                    color: 'white',
                  }}
                />
              )}
            </Box>

            {/* DISC Bar Chart */}
            <Box sx={{ mb: 3 }} aria-label="DISC scores bar chart">
              <DISCBarChart discProfile={discProfile} />
            </Box>

            {/* Screen Reader Table Alternative */}
            <Box sx={{ position: 'absolute', left: '-10000px', top: 'auto', width: '1px', height: '1px', overflow: 'hidden' }} aria-live="polite">
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>DISC Type</TableCell>
                      <TableCell>Score</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>Dominance (D)</TableCell>
                      <TableCell>{discProfile.d_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Influence (I)</TableCell>
                      <TableCell>{discProfile.i_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Steadiness (S)</TableCell>
                      <TableCell>{discProfile.s_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Compliance (C)</TableCell>
                      <TableCell>{discProfile.c_score}%</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Personality Traits */}
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" fontWeight={600} gutterBottom>
                Primary Traits
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {discProfile.personality_summary.primary_traits.map((trait) => (
                  <Chip key={trait} label={trait} size="small" />
                ))}
              </Box>
            </Box>

            {/* Communication Strategies (For Consultant) */}
            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                Communication Strategy
              </Typography>
              <Typography variant="body2">
                {discProfile.personality_summary.communication_style}
              </Typography>
            </Alert>

            {/* Report Preferences */}
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                  Report Preferences
                </Typography>
                <Typography variant="body2" paragraph>
                  <strong>Focus:</strong> {discProfile.personality_summary.report_preferences.focus}
                </Typography>
                <Typography variant="body2">
                  <strong>Visual Style:</strong> {discProfile.personality_summary.report_preferences.visual_style}
                </Typography>
              </CardContent>
            </Card>
          </Paper>
        </Grid>

        {/* Phase Results Section */}
        <Grid item xs={12} lg={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h5" component="h2" gutterBottom>
              Financial Readiness Phase
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Current focus area for financial improvement
            </Typography>

            <Divider sx={{ my: 2 }} />

            {/* Primary Phase */}
            <Box sx={{ mb: 3 }}>
              <Chip
                label={`Primary Phase: ${getPhaseName(phaseResults.primary_phase)}`}
                sx={{
                  backgroundColor: getPhaseColor(phaseResults.primary_phase),
                  color: 'white',
                  fontWeight: 600,
                  fontSize: '1rem',
                  py: 2,
                  px: 1,
                }}
              />
              {phaseResults.transition_state && (
                <Chip
                  label="In Transition"
                  color="warning"
                  sx={{ ml: 1 }}
                />
              )}
            </Box>

            {/* Phase Roadmap Visual */}
            <Box sx={{ mb: 3 }} aria-label="Financial readiness phase roadmap">
              <PhaseRoadmap phaseResults={phaseResults} />
            </Box>

            {/* Screen Reader Table Alternative for Phases */}
            <Box sx={{ position: 'absolute', left: '-10000px', top: 'auto', width: '1px', height: '1px', overflow: 'hidden' }} aria-live="polite">
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Phase</TableCell>
                      <TableCell>Score</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    <TableRow>
                      <TableCell>Stabilize</TableCell>
                      <TableCell>{phaseResults.stabilize_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Organize</TableCell>
                      <TableCell>{phaseResults.organize_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Build</TableCell>
                      <TableCell>{phaseResults.build_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Grow</TableCell>
                      <TableCell>{phaseResults.grow_score}%</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>Financial Literacy</TableCell>
                      <TableCell>{phaseResults.systemic_score}%</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Primary Phase Details */}
            {phaseResults.phase_details[phaseResults.primary_phase] && (
              <Card variant="outlined" sx={{ mb: 2 }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {phaseResults.phase_details[phaseResults.primary_phase].name}
                  </Typography>
                  <Typography variant="body2" paragraph>
                    <strong>Objective:</strong>{' '}
                    {phaseResults.phase_details[phaseResults.primary_phase].objective}
                  </Typography>
                  <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                    Key Focus Areas:
                  </Typography>
                  <List dense>
                    {phaseResults.phase_details[phaseResults.primary_phase].key_focus_areas.map(
                      (area, index) => (
                        <ListItem key={index}>
                          <ListItemText primary={`• ${area}`} />
                        </ListItem>
                      )
                    )}
                  </List>
                </CardContent>
              </Card>
            )}

            {/* Secondary Phases */}
            {phaseResults.secondary_phases.length > 0 && (
              <Alert severity="info">
                <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                  Additional Focus Areas
                </Typography>
                <Typography variant="body2">
                  {phaseResults.secondary_phases.map(getPhaseName).join(', ')}
                </Typography>
              </Alert>
            )}
          </Paper>
        </Grid>
      </Grid>

      {/* Report Generation Section */}
      <Paper sx={{ mt: 4, p: 3 }}>
        <Typography variant="h5" gutterBottom>
          <ArticleIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
          PDF Reports
        </Typography>

        {/* Error message */}
        {reportError && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setReportError(null)}>
            {reportError}
          </Alert>
        )}

        {/* Report generation not started */}
        {!consultantReportId && !clientReportId && (
          <Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Generate professional PDF reports for your client and consultant use.
            </Typography>
            <Button
              variant="contained"
              size="large"
              onClick={handleGenerateReports}
              disabled={generatingReports}
              startIcon={<ArticleIcon />}
            >
              Generate Reports
            </Button>
          </Box>
        )}

        {/* Report generation in progress or complete */}
        {(consultantReportId || clientReportId) && (
          <Grid container spacing={2}>
            {/* Consultant Report */}
            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Consultant Report
                  </Typography>

                  {consultantReportStatus === 'generating' && (
                    <Box>
                      <LinearProgress sx={{ mb: 1 }} />
                      <Typography variant="body2" color="text.secondary">
                        Generating report... This may take up to 5 seconds.
                      </Typography>
                    </Box>
                  )}

                  {consultantReportStatus === 'completed' && consultantReportUrl && (
                    <Box>
                      <Alert severity="success" sx={{ mb: 2 }}>
                        Report generated successfully!
                      </Alert>
                      <Button
                        variant="contained"
                        fullWidth
                        onClick={() => handleDownload(consultantReportUrl, 'consultant-report.pdf')}
                        startIcon={<ArticleIcon />}
                      >
                        Download Consultant Report
                      </Button>
                    </Box>
                  )}

                  {consultantReportStatus === 'failed' && (
                    <Alert severity="error">
                      Consultant report generation failed. Please try again.
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </Grid>

            {/* Client Report */}
            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Client Report
                  </Typography>

                  {clientReportStatus === 'generating' && (
                    <Box>
                      <LinearProgress sx={{ mb: 1 }} />
                      <Typography variant="body2" color="text.secondary">
                        Generating report... This may take up to 5 seconds.
                      </Typography>
                    </Box>
                  )}

                  {clientReportStatus === 'completed' && clientReportUrl && (
                    <Box>
                      <Alert severity="success" sx={{ mb: 2 }}>
                        Report generated successfully!
                      </Alert>
                      <Button
                        variant="contained"
                        fullWidth
                        onClick={() => handleDownload(clientReportUrl, 'client-report.pdf')}
                        startIcon={<ArticleIcon />}
                      >
                        Download Client Report
                      </Button>
                    </Box>
                  )}

                  {clientReportStatus === 'failed' && (
                    <Alert severity="error">
                      Client report generation failed. Please try again.
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </Grid>

            {/* Retry button if any report failed */}
            {(consultantReportStatus === 'failed' || clientReportStatus === 'failed') && (
              <Grid item xs={12}>
                <Box sx={{ textAlign: 'center' }}>
                  <Button
                    variant="outlined"
                    onClick={handleGenerateReports}
                    disabled={generatingReports}
                  >
                    Retry Failed Reports
                  </Button>
                </Box>
              </Grid>
            )}
          </Grid>
        )}
      </Paper>

      {/* Action Buttons */}
      <Box sx={{ mt: 4, display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
        <Button
          variant="outlined"
          onClick={() => navigate('/assessments')}
          startIcon={<AssessmentIcon />}
        >
          Back to Assessments
        </Button>
      </Box>
    </Container>
  );
};

/**
 * DISC Bar Chart Component
 */
interface DISCBarChartProps {
  discProfile: DISCProfileWithSummary;
}

const DISCBarChart: React.FC<DISCBarChartProps> = ({ discProfile }) => {
  const scores = [
    { type: 'D' as DISCType, label: 'Dominance', score: discProfile.d_score },
    { type: 'I' as DISCType, label: 'Influence', score: discProfile.i_score },
    { type: 'S' as DISCType, label: 'Steadiness', score: discProfile.s_score },
    { type: 'C' as DISCType, label: 'Compliance', score: discProfile.c_score },
  ];

  return (
    <Box role="img" aria-label={`DISC profile showing ${getDISCName(discProfile.primary_type)} as primary type with ${discProfile.d_score}% Dominance, ${discProfile.i_score}% Influence, ${discProfile.s_score}% Steadiness, and ${discProfile.c_score}% Compliance`}>
      {scores.map(({ type, label, score }) => (
        <Box key={type} sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
            <Typography variant="body2" fontWeight={500}>
              {label} ({type})
            </Typography>
            <Typography variant="body2" fontWeight={600}>
              {score}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={score}
            sx={{
              height: 24,
              borderRadius: 1,
              backgroundColor: 'grey.200',
              '& .MuiLinearProgress-bar': {
                backgroundColor: getDISCColor(type),
                borderRadius: 1,
              },
            }}
          />
        </Box>
      ))}
    </Box>
  );
};

/**
 * Phase Roadmap Component
 */
interface PhaseRoadmapProps {
  phaseResults: PhaseResultsWithDetails;
}

const PhaseRoadmap: React.FC<PhaseRoadmapProps> = ({ phaseResults }) => {
  const phases: Array<{ key: FinancialPhase; label: string; score: number }> = [
    { key: 'stabilize', label: 'Stabilize', score: phaseResults.stabilize_score },
    { key: 'organize', label: 'Organize', score: phaseResults.organize_score },
    { key: 'build', label: 'Build', score: phaseResults.build_score },
    { key: 'grow', label: 'Grow', score: phaseResults.grow_score },
    { key: 'systemic', label: 'Financial Literacy', score: phaseResults.systemic_score },
  ];

  const altText = `Financial readiness roadmap showing progression through five phases: ${phases.map(p => `${p.label} at ${p.score}%`).join(', ')}. Primary phase is ${getPhaseName(phaseResults.primary_phase)}.`;

  return (
    <Box role="img" aria-label={altText}>
      {phases.map((phase, index) => (
        <Box key={phase.key} sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: '50%',
                backgroundColor:
                  phase.key === phaseResults.primary_phase
                    ? getPhaseColor(phase.key)
                    : 'grey.300',
                color: phase.key === phaseResults.primary_phase ? 'white' : 'text.secondary',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 600,
                mr: 2,
              }}
            >
              {index + 1}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="body2" fontWeight={500}>
                {phase.label}
              </Typography>
            </Box>
            <Typography variant="body2" fontWeight={600}>
              {phase.score}%
            </Typography>
          </Box>
          <Box sx={{ pl: 6 }}>
            <LinearProgress
              variant="determinate"
              value={phase.score}
              sx={{
                height: 8,
                borderRadius: 1,
                backgroundColor: 'grey.200',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: getPhaseColor(phase.key),
                  borderRadius: 1,
                },
              }}
            />
          </Box>
        </Box>
      ))}
    </Box>
  );
};

export default Results;
