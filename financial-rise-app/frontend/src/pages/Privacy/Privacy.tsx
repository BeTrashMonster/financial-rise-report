import React from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Link,
  Divider,
  Button,
  List,
  ListItem,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import ArrowBackIcon from '@mui/icons-material/ArrowBack.js';
import PrivacyTipIcon from '@mui/icons-material/PrivacyTip.js';

/**
 * Privacy Policy Page
 * Comprehensive privacy disclosure including GDPR and CCPA compliance
 */
const Privacy: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: (theme) => theme.palette.neutral.gray100,
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
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 2 }}>
            <PrivacyTipIcon sx={{ fontSize: 40, color: 'primary.main' }} />
            <Typography variant="h4" component="h1" sx={{ fontWeight: 700 }}>
              Privacy Policy
            </Typography>
          </Box>

          <Typography variant="body2" color="text.secondary" gutterBottom>
            Effective Date: December 28, 2025
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Last Updated: December 28, 2025
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Introduction */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            1. Introduction
          </Typography>
          <Typography variant="body1" paragraph>
            Welcome to Financial RISE Report ("we," "our," or "us"). We are committed to protecting
            your personal information and your right to privacy. This Privacy Policy explains how we
            collect, use, disclose, and safeguard your information when you use our Financial
            Readiness Insights for Sustainable Entrepreneurship assessment platform.
          </Typography>
          <Typography variant="body1" paragraph>
            By using our services, you agree to the collection and use of information in accordance
            with this policy. If you do not agree with our policies and practices, please do not use
            our services.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Information We Collect */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            2. Information We Collect
          </Typography>
          <Typography variant="h6" gutterBottom sx={{ fontWeight: 600, marginTop: 2 }}>
            2.1 Personal Information
          </Typography>
          <Typography variant="body1" paragraph>
            We collect the following types of personal information:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Contact information (name, email address, phone number)
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Business information (company name, industry, role)</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Account credentials (username, password - encrypted)
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Assessment responses and DISC personality profile data
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Financial readiness information (encrypted at rest)
              </Typography>
            </ListItem>
          </List>

          <Typography variant="h6" gutterBottom sx={{ fontWeight: 600, marginTop: 2 }}>
            2.2 Automatically Collected Information
          </Typography>
          <Typography variant="body1" paragraph>
            When you use our platform, we automatically collect:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">IP address and device information</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Browser type and version</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Usage data and analytics</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Log files and error reports</Typography>
            </ListItem>
          </List>

          <Divider sx={{ marginY: 3 }} />

          {/* How We Use Your Information */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            3. How We Use Your Information
          </Typography>
          <Typography variant="body1" paragraph>
            We use your information to:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Provide and maintain the Financial RISE assessment service
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Generate personalized assessment reports</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Enable consultants to serve their clients</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Improve our platform and develop new features
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Send administrative and service-related communications</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Detect and prevent fraud and security threats</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Comply with legal obligations</Typography>
            </ListItem>
          </List>

          <Divider sx={{ marginY: 3 }} />

          {/* Information Sharing */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            4. Information Sharing and Disclosure
          </Typography>
          <Typography variant="body1" paragraph>
            We do not sell, rent, or trade your personal information. We may share your information
            only in the following circumstances:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>With Your Consultant:</strong> Your financial consultant who created your
                assessment has access to your responses and reports
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Service Providers:</strong> Third-party vendors who help us operate the
                platform (hosting, analytics, email) under strict confidentiality agreements
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Legal Requirements:</strong> When required by law, court order, or to protect
                our legal rights
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Business Transfers:</strong> In connection with a merger, acquisition, or sale
                of assets (with notice to you)
              </Typography>
            </ListItem>
          </List>

          <Divider sx={{ marginY: 3 }} />

          {/* Data Security */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            5. Data Security
          </Typography>
          <Typography variant="body1" paragraph>
            We implement industry-standard security measures to protect your information:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                Data encryption in transit (TLS/SSL) and at rest (AES-256)
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Secure authentication with JWT tokens</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Regular security audits and penetration testing</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Access controls and role-based permissions</Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">Secure cloud infrastructure with redundancy</Typography>
            </ListItem>
          </List>
          <Typography variant="body1" paragraph>
            While we strive to protect your information, no method of transmission over the internet
            or electronic storage is 100% secure. We cannot guarantee absolute security.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Data Retention */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            6. Data Retention
          </Typography>
          <Typography variant="body1" paragraph>
            We retain your personal information for as long as necessary to fulfill the purposes
            outlined in this Privacy Policy, unless a longer retention period is required by law. When
            you delete your account, we will delete or anonymize your personal information within 30
            days, except where we must retain it for legal compliance.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Your Rights */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            7. Your Privacy Rights
          </Typography>

          <Typography variant="h6" gutterBottom sx={{ fontWeight: 600, marginTop: 2 }}>
            7.1 GDPR Rights (European Users)
          </Typography>
          <Typography variant="body1" paragraph>
            If you are located in the European Economic Area (EEA), you have the following rights:
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right of Access:</strong> Request a copy of your personal data
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Rectification:</strong> Correct inaccurate personal data
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Erasure:</strong> Request deletion of your personal data
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Restriction:</strong> Limit how we use your data
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Data Portability:</strong> Receive your data in a portable format
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Object:</strong> Object to processing of your personal data
              </Typography>
            </ListItem>
          </List>

          <Typography variant="h6" gutterBottom sx={{ fontWeight: 600, marginTop: 2 }} id="ccpa-rights">
            7.2 CCPA Rights (California Residents)
          </Typography>
          <Typography variant="body1" paragraph>
            If you are a California resident, you have the following rights under the California
            Consumer Privacy Act (CCPA):
          </Typography>
          <List sx={{ listStyleType: 'disc', paddingLeft: 4, marginBottom: 2 }}>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Know:</strong> Request disclosure of what personal information we
                collect, use, and share
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Delete:</strong> Request deletion of your personal information
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Opt-Out:</strong> Opt-out of the sale of personal information (
                <strong>we do not sell your data</strong>)
              </Typography>
            </ListItem>
            <ListItem sx={{ display: 'list-item' }}>
              <Typography variant="body1">
                <strong>Right to Non-Discrimination:</strong> Receive equal service even if you
                exercise your privacy rights
              </Typography>
            </ListItem>
          </List>

          <Box
            sx={{
              backgroundColor: (theme) => theme.palette.primary.light,
              padding: 2,
              borderRadius: 1,
              marginTop: 2,
            }}
          >
            <Typography variant="body1" sx={{ fontWeight: 600 }}>
              We Do NOT Sell Your Personal Information
            </Typography>
            <Typography variant="body2">
              Financial RISE does not sell, rent, or trade your personal information to third parties.
              Learn more on our{' '}
              <Link href="/do-not-sell" underline="hover">
                Do Not Sell My Personal Information
              </Link>{' '}
              page.
            </Typography>
          </Box>

          <Divider sx={{ marginY: 3 }} />

          {/* Cookies */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            8. Cookies and Tracking Technologies
          </Typography>
          <Typography variant="body1" paragraph>
            We use cookies and similar tracking technologies to track activity on our platform and
            store certain information. You can instruct your browser to refuse all cookies or to
            indicate when a cookie is being sent. However, if you do not accept cookies, you may not
            be able to use some portions of our service.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Third-Party Links */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            9. Third-Party Links
          </Typography>
          <Typography variant="body1" paragraph>
            Our platform may contain links to third-party websites (e.g., external schedulers). We are
            not responsible for the privacy practices of these third parties. We encourage you to read
            their privacy policies.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Children's Privacy */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            10. Children's Privacy
          </Typography>
          <Typography variant="body1" paragraph>
            Our service is not intended for individuals under the age of 18. We do not knowingly
            collect personal information from children. If you believe we have collected information
            from a child, please contact us immediately.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Changes to Policy */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            11. Changes to This Privacy Policy
          </Typography>
          <Typography variant="body1" paragraph>
            We may update this Privacy Policy from time to time. We will notify you of any changes by
            posting the new Privacy Policy on this page and updating the "Last Updated" date. You are
            advised to review this Privacy Policy periodically for any changes.
          </Typography>

          <Divider sx={{ marginY: 3 }} />

          {/* Contact Us */}
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 600 }}>
            12. Contact Us
          </Typography>
          <Typography variant="body1" paragraph>
            If you have questions about this Privacy Policy or wish to exercise your privacy rights,
            please contact us:
          </Typography>
          <Box sx={{ marginLeft: 2, marginBottom: 2 }}>
            <Typography variant="body1">
              <strong>Email:</strong>{' '}
              <Link href="mailto:privacy@financialrise.com" underline="hover">
                privacy@financialrise.com
              </Link>
            </Typography>
            <Typography variant="body1">
              <strong>Phone:</strong> 1-800-XXX-XXXX (Privacy Hotline)
            </Typography>
            <Typography variant="body1">
              <strong>Address:</strong> Financial RISE Report, [Company Address]
            </Typography>
          </Box>

          <Divider sx={{ marginY: 3 }} />

          {/* Footer Note */}
          <Box
            sx={{
              backgroundColor: (theme) => theme.palette.neutral.gray100,
              padding: 2,
              borderRadius: 1,
              marginTop: 3,
            }}
          >
            <Typography variant="body2" color="text.secondary">
              This Privacy Policy complies with the General Data Protection Regulation (GDPR), the
              California Consumer Privacy Act (CCPA), and other applicable privacy laws. If you have
              concerns about our compliance, you may also contact your local data protection authority.
            </Typography>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
};

export default Privacy;
