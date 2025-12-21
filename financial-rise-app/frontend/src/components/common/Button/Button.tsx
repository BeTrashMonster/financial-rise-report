import React from 'react';
import { Button as MuiButton, ButtonProps as MuiButtonProps, CircularProgress } from '@mui/material';

export interface ButtonProps extends Omit<MuiButtonProps, 'size'> {
  loading?: boolean;
  size?: 'small' | 'medium' | 'large';
}

/**
 * Custom Button Component
 * Extends Material-UI Button with loading state and brand styling
 */
export const Button: React.FC<ButtonProps> = ({
  children,
  loading = false,
  disabled,
  startIcon,
  endIcon,
  size = 'medium',
  ...props
}) => {
  return (
    <MuiButton
      {...props}
      size={size}
      disabled={disabled || loading}
      startIcon={loading ? undefined : startIcon}
      endIcon={loading ? undefined : endIcon}
      aria-busy={loading}
      aria-live="polite"
    >
      {loading ? (
        <>
          <CircularProgress
            size={20}
            sx={{
              marginRight: 1,
              color: 'inherit',
            }}
          />
          Loading...
        </>
      ) : (
        children
      )}
    </MuiButton>
  );
};

export default Button;
