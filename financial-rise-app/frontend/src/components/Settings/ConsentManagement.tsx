import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Switch,
  FormControlLabel,
  FormGroup,
  Link,
  Alert,
  CircularProgress,
  Divider,
  Stack,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Collapse,
  IconButton,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import axios from 'axios';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';

interface ConsentRecord {
  id: string;
  user_id: string;
  consent_type: 'essential' | 'analytics' | 'marketing';
  granted: boolean;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  updated_at: string;
}

interface ConsentState {
  essential: boolean;
  analytics: boolean;
  marketing: boolean;
}

const ConsentManagement: React.FC = () => {
  const { user } = useSelector((state: RootState) => state.auth);
  const [consents, setConsents] = useState<ConsentState>({
    essential: true,
    analytics: false,
    marketing: false,
  });
  const [history, setHistory] = useState<ConsentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    if (user?.id) {
      fetchConsents();
    }
  }, [user]);

  const fetchConsents = async () => {
    if (!user?.id) return;

    try {
      setLoading(true);
      setError(null);

      // Fetch all consent records
      const response = await axios.get(`/api/users/${user.id}/consents`);
      const records: ConsentRecord[] = response.data;

      // Get the most recent consent for each type
      const latestConsents: ConsentState = {
        essential: true, // Essential is always true by default
        analytics: false,
        marketing: false,
      };

      records.forEach((record) => {
        // Update with the most recent consent (records are ordered by created_at DESC)
        if (latestConsents[record.consent_type] === undefined) {
          latestConsents[record.consent_type] = record.granted;
        }
      });

      setConsents(latestConsents);
      setHistory(records);
    } catch (err: any) {
      console.error('Failed to fetch consents:', err);
      setError('Failed to load consent preferences. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleConsentChange = async (type: 'essential' | 'analytics' | 'marketing', granted: boolean) => {
    if (!user?.id) return;

    // Prevent disabling essential consent
    if (type === 'essential' && !granted) {
      setError('Essential consent cannot be disabled. It is required for the application to function.');
      return;
    }

    try {
      setUpdating(type);
      setError(null);

      // Update consent via API
      await axios.patch(`/api/users/${user.id}/consents/${type}`, { granted });

      // Update local state
      setConsents((prev) => ({
        ...prev,
        [type]: granted,
      }));

      // Refresh consent history
      await fetchConsents();
    } catch (err: any) {
      console.error(`Failed to update ${type} consent:`, err);
      setError(err.response?.data?.message || `Failed to update ${type} consent. Please try again.`);

      // Revert the toggle if there was an error
      setConsents((prev) => ({
        ...prev,
        [type]: !granted,
      }));
    } finally {
      setUpdating(null);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ maxWidth: 800, margin: '0 auto', padding: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ color: '#4B006E', fontWeight: 600 }}>
        Privacy & Consent Management
      </Typography>

      <Typography variant="body1" color="text.secondary" paragraph>
        Manage your privacy preferences and consent settings. You can control how we use your data.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ mb: 2 }}>
            Your Consent Preferences
          </Typography>

          <FormGroup>
            {/* Essential Consent */}
            <Box sx={{ mb: 3 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={consents.essential}
                    onChange={(e) => handleConsentChange('essential', e.target.checked)}
                    disabled={true} // Essential consent cannot be disabled
                    color="primary"
                  />
                }
                label={
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                      Essential Processing
                      <Chip
                        label="Required"
                        size="small"
                        sx={{ ml: 1, bgcolor: '#4B006E', color: 'white' }}
                      />
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Necessary for the application to function. This includes authentication, session
                      management, and core features. Cannot be disabled.
                    </Typography>
                  </Box>
                }
              />
            </Box>

            <Divider sx={{ my: 2 }} />

            {/* Analytics Consent */}
            <Box sx={{ mb: 3 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={consents.analytics}
                    onChange={(e) => handleConsentChange('analytics', e.target.checked)}
                    disabled={updating === 'analytics'}
                    color="primary"
                  />
                }
                label={
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                      Analytics and Improvement
                      <Chip
                        label="Optional"
                        size="small"
                        variant="outlined"
                        sx={{ ml: 1 }}
                      />
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Help us improve the application by allowing us to collect anonymous usage data,
                      performance metrics, and error reports.
                    </Typography>
                  </Box>
                }
              />
              {updating === 'analytics' && <CircularProgress size={20} sx={{ ml: 2 }} />}
            </Box>

            <Divider sx={{ my: 2 }} />

            {/* Marketing Consent */}
            <Box sx={{ mb: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={consents.marketing}
                    onChange={(e) => handleConsentChange('marketing', e.target.checked)}
                    disabled={updating === 'marketing'}
                    color="primary"
                  />
                }
                label={
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                      Marketing Communications
                      <Chip
                        label="Optional"
                        size="small"
                        variant="outlined"
                        sx={{ ml: 1 }}
                      />
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Receive product updates, feature announcements, educational content, and promotional
                      communications via email.
                    </Typography>
                  </Box>
                }
              />
              {updating === 'marketing' && <CircularProgress size={20} sx={{ ml: 2 }} />}
            </Box>
          </FormGroup>

          <Alert severity="info" icon={<InfoIcon />} sx={{ mt: 3 }}>
            <Typography variant="body2">
              Your consent preferences are recorded with timestamp, IP address, and device information for
              compliance and audit purposes.{' '}
              <Link href="/privacy-policy" color="primary" underline="hover">
                Learn more in our Privacy Policy
              </Link>
            </Typography>
          </Alert>
        </CardContent>
      </Card>

      {/* Consent History */}
      <Card>
        <CardContent>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Typography variant="h6">Consent History</Typography>
            <IconButton
              onClick={() => setShowHistory(!showHistory)}
              sx={{
                transform: showHistory ? 'rotate(180deg)' : 'rotate(0deg)',
                transition: 'transform 0.3s',
              }}
            >
              <ExpandMoreIcon />
            </IconButton>
          </Box>

          <Collapse in={showHistory}>
            {history.length === 0 ? (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                No consent history available.
              </Typography>
            ) : (
              <TableContainer component={Paper} sx={{ mt: 2 }} elevation={0}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Type</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Date & Time</TableCell>
                      <TableCell>IP Address</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {history.map((record) => (
                      <TableRow key={record.id}>
                        <TableCell>
                          <Chip
                            label={record.consent_type}
                            size="small"
                            variant="outlined"
                            sx={{ textTransform: 'capitalize' }}
                          />
                        </TableCell>
                        <TableCell>
                          {record.granted ? (
                            <Chip
                              icon={<CheckCircleIcon />}
                              label="Granted"
                              size="small"
                              color="success"
                            />
                          ) : (
                            <Chip
                              icon={<CancelIcon />}
                              label="Withdrawn"
                              size="small"
                              color="error"
                            />
                          )}
                        </TableCell>
                        <TableCell>{formatDate(record.created_at)}</TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {record.ip_address || 'N/A'}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Collapse>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ConsentManagement;
