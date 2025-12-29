import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
} from '@mui/material';
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
        <Paper elevation={2} sx={{ padding: 4 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 4,
            }}
          >
            <Typography variant="h4" component="h1">
              Welcome to Dashboard
            </Typography>
            <Button variant="outlined" color="primary" onClick={handleLogout}>
              Logout
            </Button>
          </Box>

          <Typography variant="body1" paragraph>
            {user?.first_name ? `Hello, ${user.first_name}!` : 'Hello!'}
          </Typography>

          <Typography variant="body1" color="text.secondary">
            You are successfully logged in. This is your dashboard.
          </Typography>
        </Paper>
      </Container>
    </Box>
  );
};

export default Dashboard;
