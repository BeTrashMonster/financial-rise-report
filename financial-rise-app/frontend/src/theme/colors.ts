/**
 * Financial RISE Report Color Palette
 * Brand Guidelines: Purple #4B006E, Metallic Gold, Black on White
 */

export const colors = {
  // Primary Brand Colors
  primary: {
    main: '#4B006E',
    light: '#7B2FA1',
    dark: '#2E0043',
    contrastText: '#FFFFFF',
  },

  // Metallic Gold Accent
  secondary: {
    main: '#D4AF37',
    light: '#E6C85C',
    dark: '#B8941F',
    contrastText: '#000000',
  },

  // Neutral Colors
  neutral: {
    white: '#FFFFFF',
    black: '#000000',
    gray100: '#F5F5F5',
    gray200: '#EEEEEE',
    gray300: '#E0E0E0',
    gray400: '#BDBDBD',
    gray500: '#9E9E9E',
    gray600: '#757575',
    gray700: '#616161',
    gray800: '#424242',
    gray900: '#212121',
  },

  // Semantic Colors
  success: {
    main: '#2E7D32',
    light: '#4CAF50',
    dark: '#1B5E20',
    contrastText: '#FFFFFF',
  },

  warning: {
    main: '#ED6C02',
    light: '#FF9800',
    dark: '#E65100',
    contrastText: '#FFFFFF',
  },

  error: {
    main: '#D32F2F',
    light: '#EF5350',
    dark: '#C62828',
    contrastText: '#FFFFFF',
  },

  info: {
    main: '#0288D1',
    light: '#03A9F4',
    dark: '#01579B',
    contrastText: '#FFFFFF',
  },

  // Phase-Specific Colors (for visual differentiation)
  phases: {
    stabilize: '#D32F2F',   // Red - urgent, foundational
    organize: '#ED6C02',    // Orange - transitional
    build: '#FBC02D',       // Yellow - constructive
    grow: '#388E3C',        // Green - growth
    systemic: '#0288D1',    // Blue - strategic
  },

  // Background Colors
  background: {
    default: '#FFFFFF',
    paper: '#FAFAFA',
    dark: '#1A1A1A',
  },

  // Text Colors
  text: {
    primary: '#000000',
    secondary: 'rgba(0, 0, 0, 0.6)',
    disabled: 'rgba(0, 0, 0, 0.38)',
    hint: 'rgba(0, 0, 0, 0.38)',
  },

  // Border Colors
  divider: 'rgba(0, 0, 0, 0.12)',

  // Action Colors
  action: {
    active: 'rgba(0, 0, 0, 0.54)',
    hover: 'rgba(75, 0, 110, 0.04)',
    selected: 'rgba(75, 0, 110, 0.08)',
    disabled: 'rgba(0, 0, 0, 0.26)',
    disabledBackground: 'rgba(0, 0, 0, 0.12)',
    focus: 'rgba(75, 0, 110, 0.12)',
  },
};

export default colors;
