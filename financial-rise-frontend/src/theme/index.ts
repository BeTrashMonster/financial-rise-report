import { createTheme, ThemeOptions } from '@mui/material/styles';

/**
 * Financial RISE Brand Theme
 * REQ-UI-002: Purple #4B006E, metallic gold, black on white
 * REQ-UI-003: Calibri font, 14px minimum
 */

const themeOptions: ThemeOptions = {
  palette: {
    primary: {
      main: '#4B006E', // Brand purple
      light: '#7B2FA0',
      dark: '#2B004E',
      contrastText: '#FFFFFF',
    },
    secondary: {
      main: '#D4AF37', // Metallic gold
      light: '#FFD54F',
      dark: '#9C7F1E',
      contrastText: '#000000',
    },
    background: {
      default: '#FFFFFF',
      paper: '#F8F8F8',
    },
    text: {
      primary: '#000000',
      secondary: '#424242',
    },
    error: {
      main: '#D32F2F',
    },
    success: {
      main: '#388E3C',
    },
    warning: {
      main: '#F57C00',
    },
    info: {
      main: '#0288D1',
    },
  },
  typography: {
    fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
    fontSize: 14,
    h1: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '2.5rem',
      fontWeight: 600,
      color: '#4B006E',
    },
    h2: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '2rem',
      fontWeight: 600,
      color: '#4B006E',
    },
    h3: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '1.75rem',
      fontWeight: 600,
      color: '#4B006E',
    },
    h4: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '1.5rem',
      fontWeight: 600,
    },
    h5: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '1.25rem',
      fontWeight: 600,
    },
    h6: {
      fontFamily: '"Calibri", "Candara", "Segoe UI", "Arial", sans-serif',
      fontSize: '1rem',
      fontWeight: 600,
    },
    body1: {
      fontSize: '1rem', // 16px
    },
    body2: {
      fontSize: '0.875rem', // 14px - minimum per REQ-UI-003
    },
    button: {
      textTransform: 'none', // Professional, not ALL CAPS
      fontWeight: 600,
    },
  },
  shape: {
    borderRadius: 8,
  },
  spacing: 8,
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '10px 24px',
          fontSize: '1rem',
        },
        contained: {
          boxShadow: 'none',
          '&:hover': {
            boxShadow: '0 2px 8px rgba(75, 0, 110, 0.2)',
          },
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        variant: 'outlined',
      },
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: 8,
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
        },
      },
    },
  },
};

export const theme = createTheme(themeOptions);

export default theme;
