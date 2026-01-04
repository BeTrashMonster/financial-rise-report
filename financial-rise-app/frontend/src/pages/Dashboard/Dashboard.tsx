import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Grid,
  Card as MuiCard,
  CardContent,
  CardActions,
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Add as AddIcon,
  BarChart as BarChartIcon,
} from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { logout } from '@store/slices/authSlice';

/**
 * Dashboard Page
 */
const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);

  const handleLogout = async () => {
    await dispatch(logout());
    navigate('/login');
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: (theme) => theme.palette.grey[100],
        paddingY: 4,
      }}
    >
      <Container maxWidth="lg">
        {/* Page Header */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 4,
          }}
        >
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Dashboard
            </Typography>
            <Typography variant="body1" color="text.secondary">
              {user?.first_name ? `Welcome back, ${user.first_name}!` : 'Welcome back!'}
            </Typography>
          </Box>
          <Button variant="outlined" color="primary" onClick={handleLogout}>
            Logout
          </Button>
        </Box>

        {/* Quick Actions Grid */}
        <Grid container spacing={3}>
          {/* Manage Assessments Card */}
          <Grid item xs={12} sm={6} md={4}>
            <MuiCard sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flex: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    marginBottom: 2,
                  }}
                >
                  <AssessmentIcon
                    sx={{ fontSize: 40, color: 'primary.main', marginRight: 2 }}
                  />
                  <Typography variant="h6" component="h2">
                    Assessments
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  View and manage all your client financial readiness assessments
                </Typography>
              </CardContent>
              <CardActions>
                <Button
                  size="small"
                  variant="contained"
                  fullWidth
                  onClick={() => navigate('/assessments')}
                  aria-label="View all assessments"
                >
                  View All
                </Button>
              </CardActions>
            </MuiCard>
          </Grid>

          {/* Create New Assessment Card */}
          <Grid item xs={12} sm={6} md={4}>
            <MuiCard sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flex: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    marginBottom: 2,
                  }}
                >
                  <AddIcon sx={{ fontSize: 40, color: 'secondary.main', marginRight: 2 }} />
                  <Typography variant="h6" component="h2">
                    New Assessment
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Start a new financial readiness assessment for a client
                </Typography>
              </CardContent>
              <CardActions>
                <Button
                  size="small"
                  variant="contained"
                  color="secondary"
                  fullWidth
                  onClick={() => navigate('/assessments/new')}
                  aria-label="Create new assessment"
                >
                  Create New
                </Button>
              </CardActions>
            </MuiCard>
          </Grid>

          {/* Reports Card (Coming Soon) */}
          <Grid item xs={12} sm={6} md={4}>
            <MuiCard sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <CardContent sx={{ flex: 1 }}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    marginBottom: 2,
                  }}
                >
                  <BarChartIcon
                    sx={{ fontSize: 40, color: 'info.main', marginRight: 2 }}
                  />
                  <Typography variant="h6" component="h2">
                    Reports
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  View consultant and client reports for completed assessments
                </Typography>
              </CardContent>
              <CardActions>
                <Button size="small" variant="outlined" fullWidth disabled>
                  Coming Soon
                </Button>
              </CardActions>
            </MuiCard>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
};

export default Dashboard;
