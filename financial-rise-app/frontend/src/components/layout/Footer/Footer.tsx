import React from 'react';
import { Box, Container, Typography, Link, Divider } from '@mui/material';

/**
 * Application Footer Component
 * Displays copyright and links
 */
export const Footer: React.FC = () => {
  const currentYear = new Date().getFullYear();

  return (
    <Box
      component="footer"
      sx={{
        backgroundColor: (theme) => theme.palette.neutral.gray100,
        paddingY: 4,
        marginTop: 'auto',
      }}
      role="contentinfo"
    >
      <Container maxWidth="lg">
        <Divider sx={{ marginBottom: 3 }} />

        <Box
          sx={{
            display: 'flex',
            flexDirection: { xs: 'column', sm: 'row' },
            justifyContent: 'space-between',
            alignItems: { xs: 'center', sm: 'flex-start' },
            gap: 2,
          }}
        >
          <Box sx={{ textAlign: { xs: 'center', sm: 'left' } }}>
            <Typography variant="h6" gutterBottom sx={{ fontWeight: 700 }}>
              Financial RISE Report
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Readiness Insights for Sustainable Entrepreneurship
            </Typography>
          </Box>

          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              gap: 1,
              textAlign: { xs: 'center', sm: 'right' },
            }}
          >
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', justifyContent: { xs: 'center', sm: 'flex-end' } }}>
              <Link
                href="/privacy"
                color="text.secondary"
                underline="hover"
                variant="body2"
              >
                Privacy Policy
              </Link>
              <Link
                href="/terms"
                color="text.secondary"
                underline="hover"
                variant="body2"
              >
                Terms of Service
              </Link>
              <Link
                href="/contact"
                color="text.secondary"
                underline="hover"
                variant="body2"
              >
                Contact
              </Link>
            </Box>

            <Typography variant="body2" color="text.secondary">
              &copy; {currentYear} Financial RISE. All rights reserved.
            </Typography>
          </Box>
        </Box>
      </Container>
    </Box>
  );
};

export default Footer;
