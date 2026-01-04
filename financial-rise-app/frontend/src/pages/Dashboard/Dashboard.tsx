import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Grid,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Add as AddIcon,
  PlayArrow as PlayArrowIcon,
  CheckCircle as CheckCircleIcon,
  PendingActions as PendingActionsIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchAssessments } from '@store/slices/assessmentSlice';

/**
 * Get status chip color
 */
const getStatusColor = (status: string): 'default' | 'primary' | 'success' | 'warning' => {
  switch (status) {
    case 'completed':
      return 'success';
    case 'in_progress':
      return 'primary';
    case 'not_started':
      return 'default';
    default:
      return 'default';
  }
};

/**
 * Format status label
 */
const formatStatus = (status: string): string => {
  switch (status) {
    case 'completed':
      return 'Completed';
    case 'in_progress':
      return 'In Progress';
    case 'not_started':
      return 'Not Started';
    default:
      return status;
  }
};

/**
 * Format date
 */
const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
};

/**
 * Dashboard Page
 */
const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);
  const { assessments, loading, error } = useAppSelector((state) => state.assessment);

  useEffect(() => {
    dispatch(fetchAssessments());
  }, [dispatch]);

  // Calculate statistics
  const totalAssessments = assessments.length;
  const completedAssessments = assessments.filter((a) => a.status === 'completed').length;
  const inProgressAssessments = assessments.filter((a) => a.status === 'in_progress').length;

  // Get recent assessments (last 5)
  const recentAssessments = [...assessments]
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
    .slice(0, 5);

  const handleViewAssessment = (assessmentId: string, status: string) => {
    if (status === 'completed') {
      navigate(`/assessments/${assessmentId}/results`);
    } else if (status === 'in_progress') {
      navigate(`/assessments/${assessmentId}/questionnaire`);
    } else {
      navigate(`/assessments/${assessmentId}/questionnaire`);
    }
  };

  return (
    <Box
      sx={{
        backgroundColor: (theme) => theme.palette.grey[100],
        paddingY: 4,
        minHeight: 'calc(100vh - 64px)',
      }}
    >
      <Container maxWidth="xl">
        {/* Page Header */}
        <Box sx={{ marginBottom: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom fontWeight={700}>
            Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {user?.email ? `Welcome back, ${user.email.split('@')[0]}!` : 'Welcome back!'}
          </Typography>
        </Box>

        {/* Statistics Cards */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 3, bgcolor: 'primary.main', color: 'white' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AssessmentIcon sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight={700}>
                    {totalAssessments}
                  </Typography>
                  <Typography variant="body2">Total Assessments</Typography>
                </Box>
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 3, bgcolor: 'success.main', color: 'white' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <CheckCircleIcon sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight={700}>
                    {completedAssessments}
                  </Typography>
                  <Typography variant="body2">Completed</Typography>
                </Box>
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Paper sx={{ p: 3, bgcolor: 'warning.main', color: 'white' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <PendingActionsIcon sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight={700}>
                    {inProgressAssessments}
                  </Typography>
                  <Typography variant="body2">In Progress</Typography>
                </Box>
              </Box>
            </Paper>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Paper
              sx={{
                p: 3,
                bgcolor: 'secondary.main',
                color: 'white',
                cursor: 'pointer',
                transition: 'transform 0.2s',
                '&:hover': {
                  transform: 'scale(1.02)',
                },
              }}
              onClick={() => navigate('/assessments/new')}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AddIcon sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h6" fontWeight={700}>
                    New Assessment
                  </Typography>
                  <Typography variant="body2">Create new</Typography>
                </Box>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Recent Assessments */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h5" fontWeight={600}>
              Recent Assessments
            </Typography>
            <Button
              variant="outlined"
              startIcon={<AssessmentIcon />}
              onClick={() => navigate('/assessments')}
            >
              View All
            </Button>
          </Box>

          {loading && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {!loading && !error && recentAssessments.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <AssessmentIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No assessments yet
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Get started by creating your first assessment
              </Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => navigate('/assessments/new')}
              >
                Create New Assessment
              </Button>
            </Box>
          )}

          {!loading && !error && recentAssessments.length > 0 && (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Client Name</TableCell>
                    <TableCell>Email</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last Updated</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recentAssessments.map((assessment) => (
                    <TableRow key={assessment.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight={600}>
                          {assessment.client_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">{assessment.client_email}</Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={formatStatus(assessment.status)}
                          color={getStatusColor(assessment.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {formatDate(assessment.updated_at)}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={
                            assessment.status === 'completed' ? (
                              <TrendingUpIcon />
                            ) : (
                              <PlayArrowIcon />
                            )
                          }
                          onClick={() => handleViewAssessment(assessment.id, assessment.status)}
                        >
                          {assessment.status === 'completed' ? 'View Results' : 'Continue'}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>
      </Container>
    </Box>
  );
};

export default Dashboard;
