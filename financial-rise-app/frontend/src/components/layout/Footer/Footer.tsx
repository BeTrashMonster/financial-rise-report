import React from 'react';
import { Box, Container, Typography, Link, Divider } from '@mui/material';
import GppGoodIcon from '@mui/icons-material/GppGood.js';

/**
 * Application Footer Component
 * Displays copyright, legal links, and CCPA compliance notice
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

            {/* CCPA Compliance Notice - Prominent per CCPA § 1798.135 */}
            <Box
              sx={{
                display: 'flex',
                gap: 0.5,
                alignItems: 'center',
                justifyContent: { xs: 'center', sm: 'flex-end' },
                marginTop: 1,
              }}
            >
              <GppGoodIcon sx={{ fontSize: 16, color: 'primary.main' }} />
              <Link
                href="/do-not-sell"
                color="primary"
                underline="hover"
                variant="body2"
                sx={{
                  fontWeight: 600,
                  '&:hover': {
                    color: 'primary.dark',
                  },
                }}
              >
                Do Not Sell My Personal Information
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
