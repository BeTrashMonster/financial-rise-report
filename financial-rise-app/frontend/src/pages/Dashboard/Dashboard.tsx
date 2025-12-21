import React, { useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Paper,
  Button as MuiButton,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import AssessmentIcon from '@mui/icons-material/Assessment';
import PeopleIcon from '@mui/icons-material/People';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchAssessments } from '@store/slices/assessmentSlice';
import { Layout } from '@components/layout/Layout/Layout';
import Card from '@components/common/Card/Card';

/**
 * Dashboard Page Component
 * Main landing page after login
 */
export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);
  const { assessments } = useAppSelector((state) => state.assessment);

  useEffect(() => {
    dispatch(fetchAssessments());
  }, [dispatch]);

  const stats = [
    {
      title: 'Total Assessments',
      value: assessments.length,
      icon: <AssessmentIcon sx={{ fontSize: 40 }} />,
      color: '#4B006E',
    },
    {
      title: 'Completed',
      value: assessments.filter((a) => a.status === 'completed').length,
      icon: <TrendingUpIcon sx={{ fontSize: 40 }} />,
      color: '#388E3C',
    },
    {
      title: 'In Progress',
      value: assessments.filter((a) => a.status === 'in_progress').length,
      icon: <PeopleIcon sx={{ fontSize: 40 }} />,
      color: '#ED6C02',
    },
  ];

  return (
    <Layout>
      <Container maxWidth="lg">
        <Box sx={{ marginBottom: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom sx={{ fontWeight: 700 }}>
            Welcome back, {user?.name}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your client assessments and generate Financial RISE reports
          </Typography>
        </Box>

        {/* Quick Action */}
        <Box sx={{ marginBottom: 4 }}>
          <MuiButton
            variant="contained"
            color="primary"
            size="large"
            startIcon={<AddIcon />}
            onClick={() => navigate('/assessments/new')}
          >
            New Assessment
          </MuiButton>
        </Box>

        {/* Stats Cards */}
        <Grid container spacing={3} sx={{ marginBottom: 4 }}>
          {stats.map((stat, index) => (
            <Grid item xs={12} sm={6} md={4} key={index}>
              <Paper
                sx={{
                  padding: 3,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 2,
                  borderRadius: 2,
                  boxShadow: 2,
                }}
              >
                <Box
                  sx={{
                    backgroundColor: `${stat.color}15`,
                    color: stat.color,
                    padding: 2,
                    borderRadius: 2,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {stat.icon}
                </Box>
                <Box>
                  <Typography variant="h4" component="div" sx={{ fontWeight: 700 }}>
                    {stat.value}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {stat.title}
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Recent Assessments */}
        <Card title="Recent Assessments" divider>
          {assessments.length === 0 ? (
            <Box sx={{ textAlign: 'center', paddingY: 4 }}>
              <Typography variant="body1" color="text.secondary" gutterBottom>
                No assessments yet
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Create your first assessment to get started
              </Typography>
            </Box>
          ) : (
            <Box>
              {assessments.slice(0, 5).map((assessment) => (
                <Paper
                  key={assessment.id}
                  sx={{
                    padding: 2,
                    marginBottom: 2,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    '&:last-child': {
                      marginBottom: 0,
                    },
                  }}
                  variant="outlined"
                >
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {assessment.clientName}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {new Date(assessment.createdAt).toLocaleDateString()}
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      padding: '4px 12px',
                      borderRadius: 1,
                      backgroundColor:
                        assessment.status === 'completed'
                          ? '#E8F5E9'
                          : assessment.status === 'in_progress'
                          ? '#FFF3E0'
                          : '#F5F5F5',
                      color:
                        assessment.status === 'completed'
                          ? '#2E7D32'
                          : assessment.status === 'in_progress'
                          ? '#E65100'
                          : '#616161',
                    }}
                  >
                    <Typography variant="caption" sx={{ fontWeight: 600 }}>
                      {assessment.status.replace('_', ' ').toUpperCase()}
                    </Typography>
                  </Box>
                </Paper>
              ))}
            </Box>
          )}
        </Card>
      </Container>
    </Layout>
  );
};

export default Dashboard;
