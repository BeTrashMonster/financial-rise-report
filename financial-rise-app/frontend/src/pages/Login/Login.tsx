import React from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Alert,
  Link as MuiLink,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useForm, Controller } from 'react-hook-form';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { login, clearError } from '@store/slices/authSlice';
import Button from '@components/common/Button/Button';
import Input from '@components/common/Input/Input';
import { Layout } from '@components/layout/Layout/Layout';

interface LoginFormData {
  email: string;
  password: string;
}

/**
 * Login Page Component
 */
export const Login: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { loading, error } = useAppSelector((state) => state.auth);

  const {
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    defaultValues: {
      email: '',
      password: '',
    },
  });

  const onSubmit = async (data: LoginFormData) => {
    dispatch(clearError());
    const result = await dispatch(login(data));
    if (login.fulfilled.match(result)) {
      navigate('/dashboard');
    }
  };

  return (
    <Layout showHeader={false} showFooter={false}>
      <Container maxWidth="sm">
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            paddingY: 4,
          }}
        >
          <Paper
            elevation={2}
            sx={{
              padding: 4,
              borderRadius: 2,
            }}
          >
            <Box sx={{ textAlign: 'center', marginBottom: 4 }}>
              <Typography
                variant="h4"
                component="h1"
                gutterBottom
                sx={{
                  fontWeight: 700,
                  color: 'primary.main',
                }}
              >
                Financial RISE
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Sign in to your account
              </Typography>
            </Box>

            {error && (
              <Alert severity="error" sx={{ marginBottom: 3 }}>
                {error}
              </Alert>
            )}

            <form onSubmit={handleSubmit(onSubmit)} noValidate>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Controller
                  name="email"
                  control={control}
                  rules={{
                    required: 'Email is required',
                    pattern: {
                      value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                      message: 'Invalid email address',
                    },
                  }}
                  render={({ field }) => (
                    <Input
                      {...field}
                      id="email"
                      label="Email Address"
                      type="email"
                      autoComplete="email"
                      autoFocus
                      fullWidth
                      error={!!errors.email}
                      helperText={errors.email?.message}
                      disabled={loading}
                    />
                  )}
                />

                <Controller
                  name="password"
                  control={control}
                  rules={{
                    required: 'Password is required',
                    minLength: {
                      value: 8,
                      message: 'Password must be at least 8 characters',
                    },
                  }}
                  render={({ field }) => (
                    <Input
                      {...field}
                      id="password"
                      label="Password"
                      type="password"
                      autoComplete="current-password"
                      fullWidth
                      error={!!errors.password}
                      helperText={errors.password?.message}
                      disabled={loading}
                      showPasswordToggle
                    />
                  )}
                />

                <Box sx={{ textAlign: 'right' }}>
                  <MuiLink
                    href="/forgot-password"
                    variant="body2"
                    underline="hover"
                  >
                    Forgot password?
                  </MuiLink>
                </Box>

                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  color="primary"
                  size="large"
                  loading={loading}
                  sx={{ marginTop: 2 }}
                >
                  Sign In
                </Button>
              </Box>
            </form>

            <Box sx={{ marginTop: 3, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                Don't have an account?{' '}
                <MuiLink href="/register" underline="hover">
                  Sign up
                </MuiLink>
              </Typography>
            </Box>
          </Paper>
        </Box>
      </Container>
    </Layout>
  );
};

export default Login;
