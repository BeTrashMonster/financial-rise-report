import React from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Link,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Button,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import EmailIcon from '@mui/icons-material/Email';
import PhoneIcon from '@mui/icons-material/Phone';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import GppGoodIcon from '@mui/icons-material/GppGood';

/**
 * CCPA "Do Not Sell My Personal Information" Page
 * Required by CCPA § 1798.135 for California residents
 */
const DoNotSell: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: (theme) => theme.palette.neutral.gray50,
        paddingY: 4,
      }}
    >
      <Container maxWidth="md">
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate(-1)}
          sx={{ marginBottom: 3 }}
        >
          Back
        </Button>

        <Paper
          elevation={2}
          sx={{
            padding: { xs: 3, md: 5 },
            marginBottom: 4,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 3 }}>
            <GppGoodIcon sx={{ fontSize: 40, color: 'primary.main' }} />
            <Typography variant="h4" component="h1" sx={{ fontWeight: 700 }}>
              Do Not Sell My Personal Information
            </Typography>
          </Box>

          <Divider sx={{ marginBottom: 3 }} />

          {/* Notice that we do NOT sell data */}
          <Box
            sx={{
              backgroundColor: (theme) => theme.palette.success.light,
              padding: 3,
              borderRadius: 2,
              marginBottom: 4,
            }}
          >
            <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
              We Do NOT Sell Your Personal Information
            </Typography>
            <Typography variant="body1" paragraph>
              Financial RISE Report does not sell, rent, or trade your personal information to third
              parties for monetary or other valuable consideration. We are committed to protecting
              your privacy and maintaining the confidentiality of your financial assessment data.
            </Typography>
          </Box>

          {/* CCPA Rights for California Residents */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600, marginTop: 4 }}>
            Your Rights Under the California Consumer Privacy Act (CCPA)
          </Typography>

          <Typography variant="body1" paragraph>
            If you are a California resident, you have the following rights regarding your personal
            information:
          </Typography>

          <List>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutlineIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary="Right to Know"
                secondary="Request disclosure of the personal information we collect, use, and share about you."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutlineIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary="Right to Delete"
                secondary="Request deletion of your personal information, subject to certain exceptions."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutlineIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary="Right to Opt-Out"
                secondary="Opt-out of the sale of your personal information (though we do not sell data)."
              />
            </ListItem>
            <ListItem>
              <ListItemIcon>
                <CheckCircleOutlineIcon color="primary" />
              </ListItemIcon>
              <ListItemText
                primary="Right to Non-Discrimination"
                secondary="Receive equal service and pricing even if you exercise your privacy rights."
              />
            </ListItem>
          </List>

          <Divider sx={{ marginY: 3 }} />

          {/* How We Use Your Information */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600, marginTop: 4 }}>
            How We Use Your Information
          </Typography>

          <Typography variant="body1" paragraph>
            We collect and use personal information solely to:
          </Typography>

          <List sx={{ listStyleType: 'disc', paddingLeft: 4 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Provide the Financial RISE assessment and generate personalized reports
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Enable financial consultants to deliver services to their clients
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Improve our assessment tools and user experience
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Comply with legal obligations and maintain security
              </Typography>
            </ListItem>
          </List>

          <Typography variant="body1" paragraph sx={{ marginTop: 2 }}>
            We do not share your personal information with third parties except:
          </Typography>

          <List sx={{ listStyleType: 'disc', paddingLeft: 4 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                With your financial consultant who created your assessment
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                With service providers who help us operate the platform (under strict confidentiality)
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                When required by law or to protect our legal rights
              </Typography>
            </ListItem>
          </List>

          <Divider sx={{ marginY: 3 }} />

          {/* Contact Information */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600, marginTop: 4 }}>
            Exercise Your Privacy Rights
          </Typography>

          <Typography variant="body1" paragraph>
            To exercise your CCPA rights or if you have questions about our privacy practices,
            please contact us:
          </Typography>

          <Box sx={{ marginTop: 2, marginBottom: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, marginBottom: 1 }}>
              <EmailIcon color="primary" />
              <Typography variant="body1">
                Email:{' '}
                <Link href="mailto:privacy@financialrise.com" underline="hover">
                  privacy@financialrise.com
                </Link>
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <PhoneIcon color="primary" />
              <Typography variant="body1">Phone: 1-800-XXX-XXXX (Privacy Hotline)</Typography>
            </Box>
          </Box>

          <Typography variant="body2" color="text.secondary" paragraph>
            We will respond to your request within 45 days of receipt. If we need additional time
            (up to 90 days total), we will notify you of the extension and the reason.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Link to Privacy Policy */}
          <Box
            sx={{
              backgroundColor: (theme) => theme.palette.neutral.gray100,
              padding: 3,
              borderRadius: 2,
              marginTop: 4,
            }}
          >
            <Typography variant="body1" paragraph>
              For complete details about how we collect, use, and protect your personal information,
              please review our{' '}
              <Link href="/privacy" underline="hover">
                Privacy Policy
              </Link>
              .
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Last Updated: December 28, 2025
            </Typography>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
};

export default DoNotSell;
