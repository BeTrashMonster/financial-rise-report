/**
 * Server Error Page (500/502)
 * Work Stream 10a: Basic Error Handling
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Container, Typography, Button, Paper, Alert } from '@mui/material';
import {
  CloudOff as CloudOffIcon,
  Refresh as RefreshIcon,
  Home as HomeIcon,
} from '@mui/icons-material';

interface ServerErrorProps {
  type?: 'server' | 'gateway';
}

export const ServerError: React.FC<ServerErrorProps> = ({ type = 'server' }) => {
  const navigate = useNavigate();

  const errorCode = type === 'gateway' ? '502' : '500';
  const errorTitle = type === 'gateway' ? 'Bad Gateway' : 'Server Error';
  const errorMessage =
    type === 'gateway'
      ? 'The server is temporarily unable to handle your request. This is usually a temporary issue. Please try again in a few moments.'
      : 'An unexpected error occurred on our servers. Our team has been notified and is working to fix the issue.';

  const handleRefresh = () => {
    window.location.reload();
  };

  return (
    <Box
      sx={{
        minHeight: 'calc(100vh - 64px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: (theme) => theme.palette.grey[100],
        padding: 3,
      }}
    >
      <Container maxWidth="md">
        <Paper
          sx={{
            padding: { xs: 3, md: 6 },
            textAlign: 'center',
          }}
        >
          <CloudOffIcon
            sx={{
              fontSize: { xs: 80, md: 120 },
              color: 'error.main',
              marginBottom: 2,
            }}
          />
          <Typography
            variant="h1"
            component="h1"
            gutterBottom
            fontWeight={700}
            sx={{ fontSize: { xs: '3rem', md: '4rem' } }}
          >
            {errorCode}
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom fontWeight={600}>
            {errorTitle}
          </Typography>
          <Typography
            variant="body1"
            color="text.secondary"
            sx={{ marginBottom: 3, maxWidth: 500, marginX: 'auto' }}
          >
            {errorMessage}
          </Typography>

          <Alert severity="info" sx={{ marginBottom: 3, textAlign: 'left' }}>
            <Typography variant="body2" gutterBottom>
              <strong>What you can do:</strong>
            </Typography>
            <Typography variant="body2" component="ul" sx={{ margin: 0, paddingLeft: 2 }}>
              <li>Wait a few moments and try refreshing the page</li>
              <li>Check your internet connection</li>
              <li>
                If the problem persists, contact support at{' '}
                <strong>support@financialrise.com</strong>
              </li>
            </Typography>
          </Alert>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleRefresh}>
              Refresh Page
            </Button>
            <Button
              variant="contained"
              startIcon={<HomeIcon />}
              onClick={() => navigate('/dashboard')}
            >
              Go to Dashboard
            </Button>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
};

export default ServerError;
