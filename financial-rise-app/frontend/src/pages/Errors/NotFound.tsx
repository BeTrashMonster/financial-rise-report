/**
 * 404 Not Found Error Page
 * Work Stream 10a: Basic Error Handling
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Container, Typography, Button, Paper } from '@mui/material';
import {
  SearchOff as SearchOffIcon,
  Home as HomeIcon,
  ArrowBack as ArrowBackIcon,
} from '@mui/icons-material';

export const NotFound: React.FC = () => {
  const navigate = useNavigate();

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
          <SearchOffIcon
            sx={{
              fontSize: { xs: 80, md: 120 },
              color: 'text.secondary',
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
            404
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom fontWeight={600}>
            Page Not Found
          </Typography>
          <Typography
            variant="body1"
            color="text.secondary"
            sx={{ marginBottom: 4, maxWidth: 500, marginX: 'auto' }}
          >
            The page you're looking for doesn't exist or has been moved. Please check the URL or
            navigate back to the dashboard.
          </Typography>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate(-1)}
            >
              Go Back
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

export default NotFound;
