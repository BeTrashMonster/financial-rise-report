import React from 'react';
import {
  TextField,
  TextFieldProps,
  InputAdornment,
  IconButton,
} from '@mui/material';
import { Visibility, VisibilityOff } from '@mui/icons-material';

export interface InputProps extends Omit<TextFieldProps, 'variant'> {
  variant?: 'outlined' | 'filled' | 'standard';
  showPasswordToggle?: boolean;
}

/**
 * Custom Input Component
 * Extends Material-UI TextField with accessibility enhancements
 */
export const Input: React.FC<InputProps> = ({
  type = 'text',
  showPasswordToggle = false,
  variant = 'outlined',
  error,
  helperText,
  InputProps,
  ...props
}) => {
  const [showPassword, setShowPassword] = React.useState(false);

  const handleTogglePassword = () => {
    setShowPassword((prev) => !prev);
  };

  const inputType = type === 'password' && showPasswordToggle
    ? showPassword
      ? 'text'
      : 'password'
    : type;

  const endAdornment = showPasswordToggle && type === 'password' ? (
    <InputAdornment position="end">
      <IconButton
        aria-label={showPassword ? 'Hide password' : 'Show password'}
        onClick={handleTogglePassword}
        edge="end"
        tabIndex={-1}
      >
        {showPassword ? <VisibilityOff /> : <Visibility />}
      </IconButton>
    </InputAdornment>
  ) : InputProps?.endAdornment;

  return (
    <TextField
      {...props}
      type={inputType}
      variant={variant}
      error={error}
      helperText={helperText}
      InputProps={{
        ...InputProps,
        endAdornment,
      }}
      inputProps={{
        'aria-invalid': error ? 'true' : 'false',
        'aria-describedby': error ? `${props.id}-error` : undefined,
        ...props.inputProps,
      }}
      FormHelperTextProps={{
        id: error ? `${props.id}-error` : undefined,
        role: error ? 'alert' : undefined,
        ...props.FormHelperTextProps,
      }}
    />
  );
};

export default Input;
