/**
 * Financial RISE Report Typography Configuration
 * Primary Font: Calibri (14px minimum as per REQ-UI-003)
 */

import { TypographyOptions } from '@mui/material/styles/createTypography';

export const typography: TypographyOptions = {
  fontFamily: [
    'Calibri',
    'Segoe UI',
    'Roboto',
    'Helvetica Neue',
    'Arial',
    'sans-serif',
  ].join(','),

  // Base font size (14px minimum per requirements)
  fontSize: 14,

  // Heading Styles
  h1: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 700,
    fontSize: '2.5rem',      // 40px
    lineHeight: 1.2,
    letterSpacing: '-0.01562em',
  },

  h2: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 700,
    fontSize: '2rem',        // 32px
    lineHeight: 1.3,
    letterSpacing: '-0.00833em',
  },

  h3: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '1.75rem',     // 28px
    lineHeight: 1.35,
    letterSpacing: '0em',
  },

  h4: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '1.5rem',      // 24px
    lineHeight: 1.4,
    letterSpacing: '0.00735em',
  },

  h5: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '1.25rem',     // 20px
    lineHeight: 1.4,
    letterSpacing: '0em',
  },

  h6: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '1.125rem',    // 18px
    lineHeight: 1.5,
    letterSpacing: '0.0075em',
  },

  // Body Styles
  body1: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 400,
    fontSize: '1rem',        // 16px
    lineHeight: 1.5,
    letterSpacing: '0.00938em',
  },

  body2: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 400,
    fontSize: '0.875rem',    // 14px (minimum size)
    lineHeight: 1.5,
    letterSpacing: '0.01071em',
  },

  // Button Styles
  button: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '0.875rem',    // 14px
    lineHeight: 1.75,
    letterSpacing: '0.02857em',
    textTransform: 'none',   // Override MUI default uppercase
  },

  // Caption and Overline
  caption: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 400,
    fontSize: '0.875rem',    // 14px (minimum size)
    lineHeight: 1.66,
    letterSpacing: '0.03333em',
  },

  overline: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 600,
    fontSize: '0.875rem',    // 14px
    lineHeight: 2.66,
    letterSpacing: '0.08333em',
    textTransform: 'uppercase',
  },

  // Subtitle Styles
  subtitle1: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 500,
    fontSize: '1rem',        // 16px
    lineHeight: 1.75,
    letterSpacing: '0.00938em',
  },

  subtitle2: {
    fontFamily: 'Calibri, sans-serif',
    fontWeight: 500,
    fontSize: '0.875rem',    // 14px
    lineHeight: 1.57,
    letterSpacing: '0.00714em',
  },
};

export default typography;
