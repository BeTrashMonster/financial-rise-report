/**
 * User Profile Page
 * Work Stream 9: User Profile Page
 *
 * Features:
 * - Display user information
 * - Edit profile (first name, last name, email)
 * - Change password
 * - Account information display
 * - Mobile-responsive design
 */

import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  Divider,
  Alert,
  CircularProgress,
  Avatar,
  Card,
  CardContent,
} from '@mui/material';
import {
  Person as PersonIcon,
  Lock as LockIcon,
  Save as SaveIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { authService } from '@services/authService';
import { getCurrentUser } from '@store/slices/authSlice';

interface ProfileFormData {
  first_name: string;
  last_name: string;
  email: string;
}

interface PasswordFormData {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

export const UserProfile: React.FC = () => {
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);

  const [editMode, setEditMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);

  // Profile form
  const {
    control: profileControl,
    handleSubmit: handleProfileSubmit,
    formState: { errors: profileErrors },
    reset: resetProfile,
  } = useForm<ProfileFormData>({
    defaultValues: {
      first_name: user?.first_name || '',
      last_name: user?.last_name || '',
      email: user?.email || '',
    },
  });

  // Password form
  const {
    control: passwordControl,
    handleSubmit: handlePasswordSubmit,
    formState: { errors: passwordErrors },
    reset: resetPassword,
    watch,
  } = useForm<PasswordFormData>({
    defaultValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
  });

  const newPasswordValue = watch('newPassword');

  const handleUpdateProfile = async (data: ProfileFormData) => {
    try {
      setLoading(true);
      setSuccess(null);
      setError(null);

      await authService.updateProfile({
        first_name: data.first_name,
        last_name: data.last_name,
        email: data.email,
      });

      // Refresh user data
      await dispatch(getCurrentUser());

      setSuccess('Profile updated successfully!');
      setEditMode(false);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (data: PasswordFormData) => {
    try {
      setPasswordLoading(true);
      setPasswordSuccess(null);
      setPasswordError(null);

      await authService.changePassword({
        currentPassword: data.currentPassword,
        newPassword: data.newPassword,
      });

      setPasswordSuccess('Password changed successfully!');
      resetPassword();
    } catch (err: any) {
      setPasswordError(err.response?.data?.message || 'Failed to change password');
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleCancelEdit = () => {
    resetProfile({
      first_name: user?.first_name || '',
      last_name: user?.last_name || '',
      email: user?.email || '',
    });
    setEditMode(false);
    setError(null);
  };

  if (!user) {
    return (
      <Container maxWidth="lg" sx={{ py: 8, textAlign: 'center' }}>
        <CircularProgress />
      </Container>
    );
  }

  return (
    <Box
      sx={{
        backgroundColor: (theme) => theme.palette.grey[100],
        paddingY: 4,
        minHeight: 'calc(100vh - 64px)',
      }}
    >
      <Container maxWidth="lg">
        {/* Page Header */}
        <Box sx={{ marginBottom: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom fontWeight={700}>
            Profile Settings
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Manage your account information and security settings
          </Typography>
        </Box>

        <Grid container spacing={3}>
          {/* Profile Information */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 4 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h5" fontWeight={600}>
                  <PersonIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
                  Profile Information
                </Typography>
                {!editMode && (
                  <Button variant="outlined" onClick={() => setEditMode(true)}>
                    Edit Profile
                  </Button>
                )}
              </Box>

              {success && (
                <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
                  {success}
                </Alert>
              )}

              {error && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                  {error}
                </Alert>
              )}

              <form onSubmit={handleProfileSubmit(handleUpdateProfile)}>
                <Grid container spacing={3}>
                  <Grid item xs={12} sm={6}>
                    <Controller
                      name="first_name"
                      control={profileControl}
                      rules={{
                        required: 'First name is required',
                        minLength: {
                          value: 2,
                          message: 'First name must be at least 2 characters',
                        },
                      }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="First Name"
                          fullWidth
                          disabled={!editMode || loading}
                          error={!!profileErrors.first_name}
                          helperText={profileErrors.first_name?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  <Grid item xs={12} sm={6}>
                    <Controller
                      name="last_name"
                      control={profileControl}
                      rules={{
                        required: 'Last name is required',
                        minLength: {
                          value: 2,
                          message: 'Last name must be at least 2 characters',
                        },
                      }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="Last Name"
                          fullWidth
                          disabled={!editMode || loading}
                          error={!!profileErrors.last_name}
                          helperText={profileErrors.last_name?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <Controller
                      name="email"
                      control={profileControl}
                      rules={{
                        required: 'Email is required',
                        pattern: {
                          value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                          message: 'Invalid email address',
                        },
                      }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="Email"
                          type="email"
                          fullWidth
                          disabled={!editMode || loading}
                          error={!!profileErrors.email}
                          helperText={profileErrors.email?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  {editMode && (
                    <Grid item xs={12}>
                      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
                        <Button
                          variant="outlined"
                          startIcon={<CancelIcon />}
                          onClick={handleCancelEdit}
                          disabled={loading}
                        >
                          Cancel
                        </Button>
                        <Button
                          type="submit"
                          variant="contained"
                          startIcon={loading ? <CircularProgress size={20} /> : <SaveIcon />}
                          disabled={loading}
                        >
                          {loading ? 'Saving...' : 'Save Changes'}
                        </Button>
                      </Box>
                    </Grid>
                  )}
                </Grid>
              </form>
            </Paper>

            {/* Change Password */}
            <Paper sx={{ p: 4, mt: 3 }}>
              <Typography variant="h5" fontWeight={600} sx={{ mb: 3 }}>
                <LockIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
                Change Password
              </Typography>

              {passwordSuccess && (
                <Alert severity="success" sx={{ mb: 2 }} onClose={() => setPasswordSuccess(null)}>
                  {passwordSuccess}
                </Alert>
              )}

              {passwordError && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setPasswordError(null)}>
                  {passwordError}
                </Alert>
              )}

              <form onSubmit={handlePasswordSubmit(handleChangePassword)}>
                <Grid container spacing={3}>
                  <Grid item xs={12}>
                    <Controller
                      name="currentPassword"
                      control={passwordControl}
                      rules={{ required: 'Current password is required' }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="Current Password"
                          type="password"
                          fullWidth
                          disabled={passwordLoading}
                          error={!!passwordErrors.currentPassword}
                          helperText={passwordErrors.currentPassword?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <Controller
                      name="newPassword"
                      control={passwordControl}
                      rules={{
                        required: 'New password is required',
                        minLength: {
                          value: 8,
                          message: 'Password must be at least 8 characters',
                        },
                      }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="New Password"
                          type="password"
                          fullWidth
                          disabled={passwordLoading}
                          error={!!passwordErrors.newPassword}
                          helperText={passwordErrors.newPassword?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <Controller
                      name="confirmPassword"
                      control={passwordControl}
                      rules={{
                        required: 'Please confirm your new password',
                        validate: (value) =>
                          value === newPasswordValue || 'Passwords do not match',
                      }}
                      render={({ field }) => (
                        <TextField
                          {...field}
                          label="Confirm New Password"
                          type="password"
                          fullWidth
                          disabled={passwordLoading}
                          error={!!passwordErrors.confirmPassword}
                          helperText={passwordErrors.confirmPassword?.message}
                          required
                        />
                      )}
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <Button
                      type="submit"
                      variant="contained"
                      startIcon={passwordLoading ? <CircularProgress size={20} /> : <LockIcon />}
                      disabled={passwordLoading}
                    >
                      {passwordLoading ? 'Changing Password...' : 'Change Password'}
                    </Button>
                  </Grid>
                </Grid>
              </form>
            </Paper>
          </Grid>

          {/* Account Info Sidebar */}
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ textAlign: 'center', mb: 3 }}>
                  <Avatar
                    sx={{
                      width: 80,
                      height: 80,
                      margin: '0 auto 16px',
                      bgcolor: 'primary.main',
                      fontSize: '2rem',
                    }}
                  >
                    {user.first_name?.[0]?.toUpperCase() || user.email[0].toUpperCase()}
                  </Avatar>
                  <Typography variant="h6" fontWeight={600}>
                    {user.first_name} {user.last_name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {user.email}
                  </Typography>
                </Box>

                <Divider sx={{ my: 2 }} />

                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                    Account Role
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="caption" color="text.secondary" display="block" gutterBottom>
                    User ID
                  </Typography>
                  <Typography variant="body2" fontWeight={600} sx={{ wordBreak: 'break-all' }}>
                    {user.id}
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
};

export default UserProfile;
