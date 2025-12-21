import React, { useEffect } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { Provider } from 'react-redux';
import { store } from '@store/store';
import { theme } from '@theme/theme';
import { AppRoutes } from './routes';
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
    <Provider store={store}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
          <AppInit>
            <AppRoutes />
          </AppInit>
        </Router>
      </ThemeProvider>
    </Provider>
  );
};

export default App;
