import React, { useEffect } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { ThemeProvider, CssBaseline, Box } from '@mui/material';
import { Provider } from 'react-redux';
import { store } from '@store/store';
import { theme } from '@theme/theme';
import { AppRoutes } from './routes';
import { Navigation } from '@components/Navigation/Navigation';
import { ErrorBoundary } from '@components/ErrorBoundary/ErrorBoundary';
import { SkipLink } from '@components/SkipLink';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { getCurrentUser } from '@store/slices/authSlice';

/**
 * App Initialization Component
 * Handles authentication state on mount
 */
const AppInit: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const dispatch = useAppDispatch();
  const { token, isAuthenticated } = useAppSelector((state) => state.auth);

  useEffect(() => {
    // If we have a token but no user, fetch current user
    if (token && !isAuthenticated) {
      dispatch(getCurrentUser());
    }
  }, [token, isAuthenticated, dispatch]);

  return <>{children}</>;
};

/**
 * Main Application Component
 */
const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <Provider store={store}>
        <ThemeProvider theme={theme}>
          <CssBaseline />
          <Router>
            <SkipLink targetId="main-content" />
            <AppInit>
              <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
                <Navigation />
                <Box
                  id="main-content"
                  component="main"
                  tabIndex={-1}
                  sx={{ flexGrow: 1, outline: 'none' }}
                >
                  <AppRoutes />
                </Box>
              </Box>
            </AppInit>
          </Router>
        </ThemeProvider>
      </Provider>
    </ErrorBoundary>
  );
};

export default App;
