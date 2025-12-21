# Financial RISE Report - Component Specifications

**Version:** 1.0
**Date:** 2025-12-19
**Audience:** AI Agents (Claude Code) and Frontend Developers
**Purpose:** Detailed specifications for implementing reusable UI components

---

## Table of Contents

1. [Introduction](#introduction)
2. [Component Architecture](#component-architecture)
3. [Base Components](#base-components)
4. [Form Components](#form-components)
5. [Layout Components](#layout-components)
6. [Navigation Components](#navigation-components)
7. [Feedback Components](#feedback-components)
8. [Data Display Components](#data-display-components)
9. [Assessment-Specific Components](#assessment-specific-components)
10. [Implementation Examples](#implementation-examples)

---

## Introduction

This document provides implementation-ready specifications for all UI components in the Financial RISE Report application. Each component specification includes:

- **Props/API:** TypeScript interface for component props
- **States:** Interactive states and their visual treatment
- **Styling:** CSS/Material-UI styling specifications
- **Accessibility:** ARIA attributes and keyboard navigation
- **Examples:** Usage examples with code snippets
- **Testing:** Key test scenarios

### Technology Stack

- **Framework:** React 18+ with TypeScript
- **UI Library:** Material-UI (MUI) v5
- **Styling:** Emotion (CSS-in-JS via MUI)
- **Icons:** Material Icons
- **Theme:** Custom theme (see `theme/theme.ts`)

---

## Component Architecture

### File Structure

```
src/components/
├── common/           # Reusable base components
│   ├── Button/
│   ├── Input/
│   ├── Card/
│   ├── Modal/
│   └── ...
├── layout/           # Layout components
│   ├── Header/
│   ├── Sidebar/
│   ├── Footer/
│   └── Layout/
├── forms/            # Form-specific components
│   ├── TextField/
│   ├── Select/
│   ├── Checkbox/
│   └── ...
├── navigation/       # Navigation components
│   ├── Breadcrumbs/
│   ├── Tabs/
│   └── ...
├── feedback/         # Feedback components
│   ├── Alert/
│   ├── Toast/
│   ├── Loading/
│   └── ...
└── assessment/       # Assessment-specific components
    ├── QuestionCard/
    ├── ProgressBar/
    └── ...
```

### Naming Conventions

- **Component Files:** PascalCase (e.g., `Button.tsx`)
- **Component Names:** PascalCase (e.g., `<Button />`)
- **Props Interfaces:** `[ComponentName]Props` (e.g., `ButtonProps`)
- **CSS Classes:** kebab-case with BEM (e.g., `button--primary`)

---

## Base Components

### Button Component

**File:** `src/components/common/Button/Button.tsx`

#### Props Interface

```typescript
interface ButtonProps {
  // Content
  children: React.ReactNode;

  // Variant
  variant?: 'contained' | 'outlined' | 'text';

  // Color
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'warning' | 'info';

  // Size
  size?: 'small' | 'medium' | 'large';

  // State
  disabled?: boolean;
  loading?: boolean;

  // Icons
  startIcon?: React.ReactNode;
  endIcon?: React.ReactNode;

  // Behavior
  onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  type?: 'button' | 'submit' | 'reset';
  fullWidth?: boolean;

  // Accessibility
  'aria-label'?: string;
  'aria-describedby'?: string;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### States

```typescript
// Visual states
- default: Base styling
- hover: Elevated shadow, darker background
- active/pressed: Deeper background color
- focus: 2px outline, 2px offset
- disabled: Reduced opacity, no pointer events
- loading: Show spinner, disable interaction
```

#### Implementation

```tsx
import React from 'react';
import {
  Button as MuiButton,
  ButtonProps as MuiButtonProps,
  CircularProgress,
} from '@mui/material';
import { styled } from '@mui/material/styles';

interface ButtonProps extends Omit<MuiButtonProps, 'variant' | 'color'> {
  loading?: boolean;
  variant?: 'contained' | 'outlined' | 'text';
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'warning' | 'info';
}

const StyledButton = styled(MuiButton)(({ theme }) => ({
  textTransform: 'none',
  borderRadius: theme.shape.borderRadius,
  fontWeight: 600,
  fontSize: '0.875rem',
  padding: '10px 24px',
  minHeight: '40px',
  boxShadow: 'none',

  '&:hover': {
    boxShadow: 'none',
  },

  '&.MuiButton-contained:hover': {
    boxShadow: '0px 2px 4px rgba(75, 0, 110, 0.2)',
  },

  '&.MuiButton-sizeLarge': {
    padding: '12px 32px',
    fontSize: '1rem',
    minHeight: '48px',
  },

  '&.MuiButton-sizeSmall': {
    padding: '6px 16px',
    fontSize: '0.875rem',
    minHeight: '32px',
  },
}));

export const Button: React.FC<ButtonProps> = ({
  children,
  loading = false,
  disabled = false,
  startIcon,
  variant = 'contained',
  color = 'primary',
  size = 'medium',
  ...props
}) => {
  return (
    <StyledButton
      variant={variant}
      color={color}
      size={size}
      disabled={disabled || loading}
      startIcon={loading ? <CircularProgress size={20} /> : startIcon}
      {...props}
    >
      {children}
    </StyledButton>
  );
};
```

#### Usage Examples

```tsx
// Primary button
<Button variant="contained" color="primary">
  Save Assessment
</Button>

// Loading button
<Button variant="contained" loading={isSubmitting}>
  Submit
</Button>

// Button with icon
<Button variant="outlined" startIcon={<AddIcon />}>
  New Assessment
</Button>

// Full width button
<Button variant="contained" fullWidth>
  Continue
</Button>

// Disabled button
<Button variant="contained" disabled>
  Unavailable
</Button>
```

#### Accessibility

```tsx
// Icon-only button
<Button
  variant="text"
  aria-label="Close dialog"
  sx={{ minWidth: '40px', padding: '8px' }}
>
  <CloseIcon />
</Button>

// Button with description
<Button
  variant="contained"
  aria-label="Delete assessment"
  aria-describedby="delete-warning"
>
  Delete
</Button>
<span id="delete-warning" className="sr-only">
  This action cannot be undone
</span>
```

#### Testing Scenarios

1. Renders children correctly
2. Applies variant styling correctly
3. Shows loading spinner when loading=true
4. Disables interaction when disabled=true
5. Calls onClick handler when clicked
6. Prevents onClick when disabled or loading
7. Renders icons correctly
8. Applies fullWidth styling
9. Has correct ARIA attributes

---

### Card Component

**File:** `src/components/common/Card/Card.tsx`

#### Props Interface

```typescript
interface CardProps {
  // Content
  children: React.ReactNode;

  // Header
  title?: string;
  subtitle?: string;
  action?: React.ReactNode; // Header action button/icon

  // Variant
  variant?: 'elevation' | 'outlined';
  elevation?: number; // 0-24, default 1

  // Interaction
  clickable?: boolean;
  onClick?: (event: React.MouseEvent<HTMLDivElement>) => void;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;

  // Accessibility
  role?: string;
  'aria-label'?: string;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Card as MuiCard,
  CardHeader,
  CardContent,
  CardActions,
  Typography,
  CardProps as MuiCardProps,
} from '@mui/material';
import { styled } from '@mui/material/styles';

interface CardProps extends Omit<MuiCardProps, 'variant'> {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  variant?: 'elevation' | 'outlined';
  clickable?: boolean;
}

const StyledCard = styled(MuiCard, {
  shouldForwardProp: (prop) => prop !== 'clickable',
})<{ clickable?: boolean }>(({ theme, clickable }) => ({
  borderRadius: 12,
  boxShadow: '0px 2px 8px rgba(0, 0, 0, 0.08)',

  ...(clickable && {
    cursor: 'pointer',
    transition: 'box-shadow 0.2s ease-out',

    '&:hover': {
      boxShadow: '0px 4px 16px rgba(0, 0, 0, 0.12)',
    },
  }),
}));

export const Card: React.FC<CardProps> = ({
  children,
  title,
  subtitle,
  action,
  variant = 'elevation',
  clickable = false,
  onClick,
  ...props
}) => {
  return (
    <StyledCard
      variant={variant}
      clickable={clickable}
      onClick={clickable ? onClick : undefined}
      {...props}
    >
      {(title || subtitle || action) && (
        <CardHeader
          title={title}
          subheader={subtitle}
          action={action}
          titleTypographyProps={{ variant: 'h5', fontWeight: 600 }}
          subheaderTypographyProps={{ variant: 'body2' }}
        />
      )}
      <CardContent>{children}</CardContent>
    </StyledCard>
  );
};

// Export subcomponents for flexible composition
export { CardContent, CardActions } from '@mui/material';
```

#### Usage Examples

```tsx
// Simple card
<Card>
  <Typography>Card content goes here</Typography>
</Card>

// Card with header
<Card title="Assessment Summary" subtitle="Completed Dec 19, 2025">
  <Typography>Content...</Typography>
</Card>

// Card with action
<Card
  title="Recent Assessment"
  action={
    <Button variant="text" size="small">
      View
    </Button>
  }
>
  <Typography>Content...</Typography>
</Card>

// Clickable card
<Card
  title="Acme Corporation"
  clickable
  onClick={() => navigate('/assessments/123')}
>
  <Typography>Click to view details</Typography>
</Card>

// Custom composition
<Card>
  <CardContent>
    <Typography variant="h5">Custom Layout</Typography>
    <Typography>Description text</Typography>
  </CardContent>
  <CardActions>
    <Button>Action 1</Button>
    <Button>Action 2</Button>
  </CardActions>
</Card>
```

---

### Modal/Dialog Component

**File:** `src/components/common/Modal/Modal.tsx`

#### Props Interface

```typescript
interface ModalProps {
  // Visibility
  open: boolean;
  onClose: () => void;

  // Content
  title: string;
  children: React.ReactNode;

  // Actions
  actions?: React.ReactNode;

  // Size
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | false;
  fullWidth?: boolean;
  fullScreen?: boolean; // Mobile

  // Behavior
  disableBackdropClick?: boolean;
  disableEscapeKeyDown?: boolean;

  // Accessibility
  'aria-labelledby'?: string;
  'aria-describedby'?: string;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { styled } from '@mui/material/styles';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  actions?: React.ReactNode;
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | false;
  fullWidth?: boolean;
  disableBackdropClick?: boolean;
}

const StyledDialog = styled(Dialog)(({ theme }) => ({
  '& .MuiDialog-paper': {
    borderRadius: 16,
    padding: theme.spacing(4),
  },
}));

const StyledDialogTitle = styled(DialogTitle)(({ theme }) => ({
  padding: 0,
  paddingBottom: theme.spacing(2),
  marginBottom: theme.spacing(3),
  borderBottom: `1px solid ${theme.palette.divider}`,
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
}));

const StyledDialogActions = styled(DialogActions)(({ theme }) => ({
  padding: 0,
  paddingTop: theme.spacing(2),
  marginTop: theme.spacing(3),
  borderTop: `1px solid ${theme.palette.divider}`,
  justifyContent: 'flex-end',
  gap: theme.spacing(2),
}));

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  children,
  actions,
  maxWidth = 'sm',
  fullWidth = true,
  disableBackdropClick = false,
  ...props
}) => {
  const theme = useTheme();
  const fullScreen = useMediaQuery(theme.breakpoints.down('sm'));

  const handleClose = (event: {}, reason: 'backdropClick' | 'escapeKeyDown') => {
    if (reason === 'backdropClick' && disableBackdropClick) {
      return;
    }
    onClose();
  };

  return (
    <StyledDialog
      open={open}
      onClose={handleClose}
      maxWidth={maxWidth}
      fullWidth={fullWidth}
      fullScreen={fullScreen}
      aria-labelledby="modal-title"
      {...props}
    >
      <StyledDialogTitle id="modal-title">
        {title}
        <IconButton
          aria-label="Close dialog"
          onClick={onClose}
          size="small"
        >
          <CloseIcon />
        </IconButton>
      </StyledDialogTitle>

      <DialogContent sx={{ padding: 0 }}>
        {children}
      </DialogContent>

      {actions && (
        <StyledDialogActions>
          {actions}
        </StyledDialogActions>
      )}
    </StyledDialog>
  );
};
```

#### Usage Examples

```tsx
// Basic modal
<Modal
  open={isOpen}
  onClose={handleClose}
  title="Confirm Action"
>
  <Typography>Are you sure you want to proceed?</Typography>
</Modal>

// Modal with actions
<Modal
  open={isOpen}
  onClose={handleClose}
  title="Delete Assessment"
  actions={
    <>
      <Button variant="outlined" onClick={handleClose}>
        Cancel
      </Button>
      <Button variant="contained" color="error" onClick={handleDelete}>
        Delete
      </Button>
    </>
  }
>
  <Typography>This action cannot be undone.</Typography>
</Modal>

// Form modal
<Modal
  open={isOpen}
  onClose={handleClose}
  title="Create New Assessment"
  maxWidth="md"
  actions={
    <>
      <Button variant="text" onClick={handleClose}>
        Cancel
      </Button>
      <Button variant="contained" onClick={handleSubmit}>
        Create
      </Button>
    </>
  }
>
  <form>
    <TextField label="Client Name" fullWidth />
    <TextField label="Business Name" fullWidth />
  </form>
</Modal>
```

---

## Form Components

### TextField Component

**File:** `src/components/forms/TextField/TextField.tsx`

#### Props Interface

```typescript
interface TextFieldProps {
  // Value
  value: string;
  onChange: (event: React.ChangeEvent<HTMLInputElement>) => void;

  // Label & Placeholder
  label: string;
  placeholder?: string;
  helperText?: string;

  // Validation
  required?: boolean;
  error?: boolean;
  errorText?: string;

  // Type
  type?: 'text' | 'email' | 'password' | 'number' | 'tel' | 'url';
  multiline?: boolean;
  rows?: number;
  maxRows?: number;

  // State
  disabled?: boolean;
  readOnly?: boolean;

  // Input props
  inputProps?: InputBaseComponentProps;
  InputProps?: Partial<OutlinedInputProps>;

  // Icons
  startAdornment?: React.ReactNode;
  endAdornment?: React.ReactNode;

  // Sizing
  fullWidth?: boolean;
  size?: 'small' | 'medium';

  // Accessibility
  'aria-label'?: string;
  'aria-describedby'?: string;
  'aria-required'?: boolean;
  'aria-invalid'?: boolean;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  TextField as MuiTextField,
  TextFieldProps as MuiTextFieldProps,
  InputAdornment,
} from '@mui/material';
import { styled } from '@mui/material/styles';

interface TextFieldProps extends Omit<MuiTextFieldProps, 'variant'> {
  errorText?: string;
  startAdornment?: React.ReactNode;
  endAdornment?: React.ReactNode;
}

const StyledTextField = styled(MuiTextField)(({ theme }) => ({
  '& .MuiOutlinedInput-root': {
    borderRadius: 8,
    fontSize: '0.875rem',

    '&:hover .MuiOutlinedInput-notchedOutline': {
      borderColor: theme.palette.primary.main,
    },

    '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
      borderWidth: 2,
    },
  },

  '& .MuiOutlinedInput-input': {
    padding: '12px 14px',
  },

  '& .MuiInputLabel-root': {
    fontSize: '0.875rem',
    fontWeight: 500,
  },

  '& .MuiFormHelperText-root': {
    fontSize: '0.875rem',
    marginTop: theme.spacing(0.5),
  },
}));

export const TextField: React.FC<TextFieldProps> = ({
  error,
  errorText,
  helperText,
  startAdornment,
  endAdornment,
  required,
  ...props
}) => {
  const hasError = error || Boolean(errorText);
  const displayHelperText = hasError ? errorText : helperText;

  const InputProps = {
    ...props.InputProps,
    ...(startAdornment && {
      startAdornment: (
        <InputAdornment position="start">
          {startAdornment}
        </InputAdornment>
      ),
    }),
    ...(endAdornment && {
      endAdornment: (
        <InputAdornment position="end">
          {endAdornment}
        </InputAdornment>
      ),
    }),
  };

  return (
    <StyledTextField
      variant="outlined"
      error={hasError}
      helperText={displayHelperText}
      required={required}
      InputProps={InputProps}
      aria-required={required}
      aria-invalid={hasError}
      {...props}
    />
  );
};
```

#### Usage Examples

```tsx
// Basic text input
<TextField
  label="Client Name"
  value={clientName}
  onChange={(e) => setClientName(e.target.value)}
  fullWidth
/>

// Required field
<TextField
  label="Email Address"
  type="email"
  value={email}
  onChange={(e) => setEmail(e.target.value)}
  required
  fullWidth
/>

// Field with error
<TextField
  label="Email Address"
  type="email"
  value={email}
  onChange={(e) => setEmail(e.target.value)}
  error
  errorText="Please enter a valid email address"
  fullWidth
/>

// Field with helper text
<TextField
  label="Phone Number"
  type="tel"
  value={phone}
  onChange={(e) => setPhone(e.target.value)}
  helperText="We'll use this to send you appointment reminders"
  fullWidth
/>

// Multiline textarea
<TextField
  label="Consultant Notes"
  value={notes}
  onChange={(e) => setNotes(e.target.value)}
  multiline
  rows={4}
  placeholder="Add private notes (only visible in consultant report)"
  fullWidth
/>

// Field with icon adornment
<TextField
  label="Search"
  value={searchTerm}
  onChange={(e) => setSearchTerm(e.target.value)}
  startAdornment={<SearchIcon />}
  placeholder="Search assessments..."
  fullWidth
/>
```

---

### Checkbox Component

**File:** `src/components/forms/Checkbox/Checkbox.tsx`

#### Props Interface

```typescript
interface CheckboxProps {
  // Value
  checked: boolean;
  onChange: (event: React.ChangeEvent<HTMLInputElement>, checked: boolean) => void;

  // Label
  label: string | React.ReactNode;

  // State
  disabled?: boolean;
  indeterminate?: boolean; // For "select all" scenarios

  // Validation
  required?: boolean;
  error?: boolean;

  // Accessibility
  'aria-label'?: string;
  'aria-describedby'?: string;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Checkbox as MuiCheckbox,
  FormControlLabel,
  FormHelperText,
  CheckboxProps as MuiCheckboxProps,
} from '@mui/material';
import { styled } from '@mui/material/styles';

interface CheckboxProps extends Omit<MuiCheckboxProps, 'onChange'> {
  label: string | React.ReactNode;
  onChange: (event: React.ChangeEvent<HTMLInputElement>, checked: boolean) => void;
  error?: boolean;
  helperText?: string;
}

const StyledFormControlLabel = styled(FormControlLabel)(({ theme }) => ({
  marginLeft: 0,
  marginRight: 0,

  '& .MuiCheckbox-root': {
    padding: theme.spacing(1),
  },

  '& .MuiFormControlLabel-label': {
    fontSize: '0.875rem',
    marginLeft: theme.spacing(1),
  },
}));

export const Checkbox: React.FC<CheckboxProps> = ({
  label,
  error,
  helperText,
  ...props
}) => {
  return (
    <>
      <StyledFormControlLabel
        control={
          <MuiCheckbox
            color="primary"
            sx={{
              '&.Mui-checked': {
                color: (theme) => theme.palette.primary.main,
              },
            }}
            {...props}
          />
        }
        label={label}
      />
      {helperText && (
        <FormHelperText error={error}>
          {helperText}
        </FormHelperText>
      )}
    </>
  );
};
```

#### Usage Examples

```tsx
// Basic checkbox
<Checkbox
  label="Remember me"
  checked={rememberMe}
  onChange={(e, checked) => setRememberMe(checked)}
/>

// Required checkbox
<Checkbox
  label="I agree to the terms and conditions"
  checked={agreedToTerms}
  onChange={(e, checked) => setAgreedToTerms(checked)}
  required
/>

// Checkbox with error
<Checkbox
  label="Send welcome email"
  checked={sendEmail}
  onChange={(e, checked) => setSendEmail(checked)}
  error
  helperText="Email service is currently unavailable"
/>

// Not Applicable checkbox (assessment specific)
<Checkbox
  label="Not Applicable"
  checked={isNotApplicable}
  onChange={(e, checked) => setIsNotApplicable(checked)}
/>
```

---

### Radio Group Component

**File:** `src/components/forms/RadioGroup/RadioGroup.tsx`

#### Props Interface

```typescript
interface RadioOption {
  value: string;
  label: string | React.ReactNode;
  disabled?: boolean;
}

interface RadioGroupProps {
  // Value
  value: string;
  onChange: (event: React.ChangeEvent<HTMLInputElement>, value: string) => void;

  // Options
  options: RadioOption[];

  // Label
  label?: string;

  // Layout
  row?: boolean; // Horizontal layout

  // Validation
  required?: boolean;
  error?: boolean;
  helperText?: string;

  // Accessibility
  'aria-label'?: string;
  'aria-describedby'?: string;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Radio,
  RadioGroup as MuiRadioGroup,
  FormControl,
  FormControlLabel,
  FormLabel,
  FormHelperText,
} from '@mui/material';

interface RadioOption {
  value: string;
  label: string | React.ReactNode;
  disabled?: boolean;
}

interface RadioGroupProps {
  value: string;
  onChange: (event: React.ChangeEvent<HTMLInputElement>, value: string) => void;
  options: RadioOption[];
  label?: string;
  row?: boolean;
  required?: boolean;
  error?: boolean;
  helperText?: string;
}

export const RadioGroup: React.FC<RadioGroupProps> = ({
  value,
  onChange,
  options,
  label,
  row = false,
  required = false,
  error = false,
  helperText,
  ...props
}) => {
  return (
    <FormControl error={error} required={required} fullWidth>
      {label && <FormLabel>{label}</FormLabel>}
      <MuiRadioGroup
        value={value}
        onChange={onChange}
        row={row}
        {...props}
      >
        {options.map((option) => (
          <FormControlLabel
            key={option.value}
            value={option.value}
            control={<Radio />}
            label={option.label}
            disabled={option.disabled}
          />
        ))}
      </MuiRadioGroup>
      {helperText && <FormHelperText>{helperText}</FormHelperText>}
    </FormControl>
  );
};
```

#### Usage Examples

```tsx
// Basic radio group
<RadioGroup
  label="Business Entity Type"
  value={entityType}
  onChange={(e, value) => setEntityType(value)}
  options={[
    { value: 'sole_prop', label: 'Sole Proprietorship' },
    { value: 'llc', label: 'LLC' },
    { value: 's_corp', label: 'S-Corporation' },
    { value: 'c_corp', label: 'C-Corporation' },
  ]}
/>

// Horizontal radio group (rating scale)
<RadioGroup
  label="How confident are you in your financial processes?"
  value={confidence}
  onChange={(e, value) => setConfidence(value)}
  row
  options={[
    { value: '1', label: '1' },
    { value: '2', label: '2' },
    { value: '3', label: '3' },
    { value: '4', label: '4' },
    { value: '5', label: '5' },
  ]}
/>

// Required with error
<RadioGroup
  label="Role *"
  value={role}
  onChange={(e, value) => setRole(value)}
  required
  error
  helperText="Please select a role"
  options={[
    { value: 'consultant', label: 'Consultant' },
    { value: 'admin', label: 'Administrator' },
  ]}
/>
```

---

## Layout Components

### Header Component

**File:** `src/components/layout/Header/Header.tsx`

#### Props Interface

```typescript
interface HeaderProps {
  // User info
  user?: {
    name: string;
    email: string;
    avatar?: string;
    role: 'consultant' | 'admin';
  };

  // Navigation (desktop only)
  showNavigation?: boolean;

  // Callbacks
  onLogout?: () => void;
  onProfileClick?: () => void;
  onMenuToggle?: () => void; // Mobile menu toggle

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  IconButton,
  Avatar,
  Menu,
  MenuItem,
  Typography,
  Box,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import LogoutIcon from '@mui/icons-material/Logout';

interface HeaderProps {
  user?: {
    name: string;
    email: string;
    avatar?: string;
    role: 'consultant' | 'admin';
  };
  onLogout?: () => void;
  onMenuToggle?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  user,
  onLogout,
  onMenuToggle,
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    handleMenuClose();
    onLogout?.();
  };

  return (
    <AppBar position="sticky" color="default" elevation={0}>
      <Toolbar sx={{ justifyContent: 'space-between' }}>
        {/* Left: Logo + Mobile Menu */}
        <Box display="flex" alignItems="center" gap={2}>
          {isMobile && (
            <IconButton
              edge="start"
              aria-label="Open menu"
              onClick={onMenuToggle}
            >
              <MenuIcon />
            </IconButton>
          )}

          <Box display="flex" alignItems="center" gap={1}>
            {/* Logo */}
            <Typography
              variant="h6"
              component="div"
              sx={{
                fontWeight: 700,
                color: 'primary.main',
                display: 'flex',
                alignItems: 'center',
              }}
            >
              Financial RISE
            </Typography>
          </Box>
        </Box>

        {/* Right: User Menu */}
        {user && (
          <>
            <IconButton
              onClick={handleMenuClick}
              aria-label="User menu"
              aria-controls="user-menu"
              aria-haspopup="true"
            >
              {user.avatar ? (
                <Avatar src={user.avatar} alt={user.name} />
              ) : (
                <Avatar>{user.name[0]}</Avatar>
              )}
            </IconButton>

            <Menu
              id="user-menu"
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'right',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
            >
              <Box sx={{ px: 2, py: 1 }}>
                <Typography variant="subtitle2" fontWeight={600}>
                  {user.name}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {user.email}
                </Typography>
              </Box>

              <MenuItem onClick={handleLogout}>
                <LogoutIcon sx={{ mr: 1 }} fontSize="small" />
                Logout
              </MenuItem>
            </Menu>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};
```

---

### Sidebar Component

**File:** `src/components/layout/Sidebar/Sidebar.tsx`

#### Props Interface

```typescript
interface SidebarProps {
  // Items
  items: SidebarItem[];

  // State
  open: boolean;
  onClose?: () => void; // Mobile only

  // Current route
  activePath: string;

  // Styling
  width?: number;
  className?: string;
  sx?: SxProps<Theme>;
}

interface SidebarItem {
  label: string;
  icon?: React.ReactNode;
  path: string;
  badge?: number; // Notification badge
  divider?: boolean; // Show divider after item
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Badge,
  Divider,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';

interface SidebarItem {
  label: string;
  icon?: React.ReactNode;
  path: string;
  badge?: number;
  divider?: boolean;
}

interface SidebarProps {
  items: SidebarItem[];
  open: boolean;
  onClose?: () => void;
  width?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  items,
  open,
  onClose,
  width = 240,
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const navigate = useNavigate();
  const location = useLocation();

  const handleItemClick = (path: string) => {
    navigate(path);
    if (isMobile) {
      onClose?.();
    }
  };

  const drawer = (
    <List sx={{ pt: 2 }}>
      {items.map((item, index) => (
        <React.Fragment key={item.path}>
          <ListItem disablePadding>
            <ListItemButton
              selected={location.pathname === item.path}
              onClick={() => handleItemClick(item.path)}
              sx={{
                mx: 1,
                borderRadius: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(75, 0, 110, 0.08)',
                  borderLeft: `4px solid ${theme.palette.primary.main}`,
                  '&:hover': {
                    backgroundColor: 'rgba(75, 0, 110, 0.12)',
                  },
                },
              }}
            >
              {item.icon && (
                <ListItemIcon
                  sx={{
                    color: location.pathname === item.path
                      ? 'primary.main'
                      : 'text.secondary',
                  }}
                >
                  {item.badge ? (
                    <Badge badgeContent={item.badge} color="error">
                      {item.icon}
                    </Badge>
                  ) : (
                    item.icon
                  )}
                </ListItemIcon>
              )}
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontSize: '0.875rem',
                  fontWeight: location.pathname === item.path ? 600 : 500,
                  color: location.pathname === item.path
                    ? 'primary.main'
                    : 'text.primary',
                }}
              />
            </ListItemButton>
          </ListItem>
          {item.divider && <Divider sx={{ my: 1 }} />}
        </React.Fragment>
      ))}
    </List>
  );

  return (
    <>
      {/* Mobile drawer */}
      {isMobile ? (
        <Drawer
          variant="temporary"
          open={open}
          onClose={onClose}
          ModalProps={{
            keepMounted: true, // Better mobile performance
          }}
          sx={{
            '& .MuiDrawer-paper': {
              width,
              boxSizing: 'border-box',
              backgroundColor: 'background.paper',
              borderRight: `1px solid ${theme.palette.divider}`,
            },
          }}
        >
          {drawer}
        </Drawer>
      ) : (
        /* Desktop drawer */
        <Drawer
          variant="permanent"
          sx={{
            width,
            flexShrink: 0,
            '& .MuiDrawer-paper': {
              width,
              boxSizing: 'border-box',
              backgroundColor: 'background.paper',
              borderRight: `1px solid ${theme.palette.divider}`,
              top: 64, // Below header
            },
          }}
        >
          {drawer}
        </Drawer>
      )}
    </>
  );
};
```

#### Usage Example

```tsx
import DashboardIcon from '@mui/icons-material/Dashboard';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SettingsIcon from '@mui/icons-material/Settings';

const sidebarItems = [
  {
    label: 'Dashboard',
    icon: <DashboardIcon />,
    path: '/dashboard',
  },
  {
    label: 'Assessments',
    icon: <AssessmentIcon />,
    path: '/assessments',
    badge: 3, // 3 in progress
  },
  {
    label: 'Settings',
    icon: <SettingsIcon />,
    path: '/settings',
    divider: true,
  },
];

<Sidebar
  items={sidebarItems}
  open={sidebarOpen}
  onClose={() => setSidebarOpen(false)}
/>
```

---

## Feedback Components

### Alert Component

**File:** `src/components/feedback/Alert/Alert.tsx`

#### Props Interface

```typescript
interface AlertProps {
  // Content
  children: React.ReactNode;
  title?: string;

  // Severity
  severity: 'success' | 'error' | 'warning' | 'info';

  // Variant
  variant?: 'standard' | 'filled' | 'outlined';

  // Dismissible
  onClose?: () => void;

  // Icon
  icon?: React.ReactNode | false; // false to hide icon

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Alert as MuiAlert,
  AlertTitle,
  AlertProps as MuiAlertProps,
} from '@mui/material';
import { styled } from '@mui/material/styles';

interface AlertProps extends MuiAlertProps {
  title?: string;
}

const StyledAlert = styled(MuiAlert)(({ theme }) => ({
  borderRadius: 8,
  padding: '12px 16px',

  '&.MuiAlert-standardSuccess': {
    backgroundColor: '#E8F5E9',
    borderLeft: `4px solid ${theme.palette.success.main}`,
  },

  '&.MuiAlert-standardWarning': {
    backgroundColor: '#FFF3E0',
    borderLeft: `4px solid ${theme.palette.warning.main}`,
  },

  '&.MuiAlert-standardError': {
    backgroundColor: '#FFEBEE',
    borderLeft: `4px solid ${theme.palette.error.main}`,
  },

  '&.MuiAlert-standardInfo': {
    backgroundColor: '#E3F2FD',
    borderLeft: `4px solid ${theme.palette.info.main}`,
  },
}));

export const Alert: React.FC<AlertProps> = ({
  children,
  title,
  ...props
}) => {
  return (
    <StyledAlert {...props}>
      {title && <AlertTitle>{title}</AlertTitle>}
      {children}
    </StyledAlert>
  );
};
```

#### Usage Examples

```tsx
// Success alert
<Alert severity="success">
  Assessment completed successfully!
</Alert>

// Error alert with title
<Alert severity="error" title="Validation Error">
  Please correct the errors below before submitting.
</Alert>

// Warning alert, dismissible
<Alert severity="warning" onClose={() => setShowWarning(false)}>
  Your session will expire in 5 minutes.
</Alert>

// Info alert
<Alert severity="info">
  This assessment will take approximately 30-45 minutes to complete.
</Alert>
```

---

### Loading Spinner Component

**File:** `src/components/feedback/Loading/Loading.tsx`

#### Props Interface

```typescript
interface LoadingProps {
  // Size
  size?: number; // diameter in pixels

  // Variant
  variant?: 'circular' | 'linear';

  // Message
  message?: string;

  // Color
  color?: 'primary' | 'secondary' | 'inherit';

  // Fullscreen overlay
  fullscreen?: boolean;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  CircularProgress,
  LinearProgress,
  Box,
  Typography,
  Backdrop,
} from '@mui/material';

interface LoadingProps {
  size?: number;
  variant?: 'circular' | 'linear';
  message?: string;
  color?: 'primary' | 'secondary' | 'inherit';
  fullscreen?: boolean;
}

export const Loading: React.FC<LoadingProps> = ({
  size = 40,
  variant = 'circular',
  message,
  color = 'primary',
  fullscreen = false,
}) => {
  const loadingContent = (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      gap={2}
    >
      {variant === 'circular' ? (
        <CircularProgress size={size} color={color} />
      ) : (
        <LinearProgress
          color={color}
          sx={{ width: '100%', maxWidth: 300 }}
        />
      )}
      {message && (
        <Typography variant="body2" color="text.secondary">
          {message}
        </Typography>
      )}
    </Box>
  );

  if (fullscreen) {
    return (
      <Backdrop
        open
        sx={{
          color: '#fff',
          zIndex: (theme) => theme.zIndex.drawer + 1,
          backgroundColor: 'rgba(255, 255, 255, 0.9)',
        }}
      >
        {loadingContent}
      </Backdrop>
    );
  }

  return loadingContent;
};
```

#### Usage Examples

```tsx
// Circular spinner
<Loading />

// Linear progress bar
<Loading variant="linear" />

// With message
<Loading message="Loading assessments..." />

// Fullscreen loading
<Loading fullscreen message="Generating reports..." />

// Inside button
<Button disabled startIcon={<CircularProgress size={20} />}>
  Loading...
</Button>
```

---

## Assessment-Specific Components

### QuestionCard Component

**File:** `src/components/assessment/QuestionCard/QuestionCard.tsx`

#### Props Interface

```typescript
interface QuestionCardProps {
  // Question data
  question: {
    id: string;
    text: string;
    type: 'single_choice' | 'multiple_choice' | 'rating' | 'text';
    options?: string[];
    required: boolean;
  };

  // Section info
  section: {
    name: string;
    color: string; // Phase color
    questionNumber: number;
    totalQuestions: number;
  };

  // Value
  value: any;
  onChange: (value: any) => void;

  // Not Applicable
  isNotApplicable: boolean;
  onNotApplicableChange: (checked: boolean) => void;

  // Consultant Notes
  notes: string;
  onNotesChange: (notes: string) => void;

  // Styling
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import {
  Box,
  Typography,
  RadioGroup,
  FormControlLabel,
  Radio,
  Checkbox,
  TextField,
  Rating,
} from '@mui/material';
import { Card } from '../../common/Card/Card';

interface QuestionCardProps {
  question: {
    id: string;
    text: string;
    type: 'single_choice' | 'multiple_choice' | 'rating' | 'text';
    options?: string[];
    required: boolean;
  };
  section: {
    name: string;
    color: string;
    questionNumber: number;
    totalQuestions: number;
  };
  value: any;
  onChange: (value: any) => void;
  isNotApplicable: boolean;
  onNotApplicableChange: (checked: boolean) => void;
  notes: string;
  onNotesChange: (notes: string) => void;
}

export const QuestionCard: React.FC<QuestionCardProps> = ({
  question,
  section,
  value,
  onChange,
  isNotApplicable,
  onNotApplicableChange,
  notes,
  onNotesChange,
}) => {
  const renderInput = () => {
    if (isNotApplicable) {
      return null; // Hide input when N/A is checked
    }

    switch (question.type) {
      case 'single_choice':
        return (
          <RadioGroup value={value || ''} onChange={(e) => onChange(e.target.value)}>
            {question.options?.map((option) => (
              <FormControlLabel
                key={option}
                value={option}
                control={<Radio />}
                label={option}
              />
            ))}
          </RadioGroup>
        );

      case 'rating':
        return (
          <Box>
            <Rating
              value={Number(value) || 0}
              onChange={(e, newValue) => onChange(newValue)}
              size="large"
            />
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
              1 = Strongly Disagree, 5 = Strongly Agree
            </Typography>
          </Box>
        );

      case 'text':
        return (
          <TextField
            value={value || ''}
            onChange={(e) => onChange(e.target.value)}
            multiline
            rows={4}
            fullWidth
            placeholder="Enter your response..."
          />
        );

      default:
        return null;
    }
  };

  return (
    <Card
      sx={{
        maxWidth: 800,
        mx: 'auto',
        borderLeft: `4px solid ${section.color}`,
      }}
    >
      {/* Section Header */}
      <Box sx={{ mb: 3 }}>
        <Typography
          variant="h5"
          sx={{
            color: section.color,
            fontWeight: 600,
            pb: 1,
            borderBottom: `2px solid ${section.color}`,
          }}
        >
          {section.name}
        </Typography>
      </Box>

      {/* Question Number */}
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Question {section.questionNumber} of {section.totalQuestions}
      </Typography>

      {/* Question Text */}
      <Typography variant="h6" sx={{ mb: 3, lineHeight: 1.5 }}>
        {question.text}
        {question.required && (
          <span style={{ color: '#D32F2F' }}> *</span>
        )}
      </Typography>

      {/* Answer Input */}
      {renderInput()}

      {/* Not Applicable */}
      <Box sx={{ mt: 2 }}>
        <FormControlLabel
          control={
            <Checkbox
              checked={isNotApplicable}
              onChange={(e) => onNotApplicableChange(e.target.checked)}
            />
          }
          label="Not Applicable"
        />
      </Box>

      {/* Consultant Notes */}
      <Box sx={{ mt: 3, pt: 3, borderTop: '1px solid #E0E0E0' }}>
        <TextField
          label="Consultant Notes (Optional)"
          value={notes}
          onChange={(e) => onNotesChange(e.target.value)}
          multiline
          rows={3}
          fullWidth
          placeholder="Add private notes (only visible in consultant report)"
          sx={{
            backgroundColor: '#FAFAFA',
          }}
        />
      </Box>

      {/* Auto-save indicator */}
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
        ✓ Last saved: 2 minutes ago
      </Typography>
    </Card>
  );
};
```

---

### ProgressBar Component

**File:** `src/components/assessment/ProgressBar/ProgressBar.tsx`

#### Props Interface

```typescript
interface ProgressBarProps {
  // Progress
  current: number;
  total: number;
  percentage: number; // 0-100

  // Label
  label?: string;
  showPercentage?: boolean;
  showCount?: boolean;

  // Color
  color?: 'primary' | 'secondary' | string; // Hex color

  // Styling
  height?: number;
  className?: string;
  sx?: SxProps<Theme>;
}
```

#### Implementation

```tsx
import React from 'react';
import { Box, LinearProgress, Typography } from '@mui/material';
import { styled } from '@mui/material/styles';

interface ProgressBarProps {
  current: number;
  total: number;
  percentage: number;
  label?: string;
  showPercentage?: boolean;
  showCount?: boolean;
  color?: string;
  height?: number;
}

const StyledLinearProgress = styled(LinearProgress)<{ barColor?: string; barHeight?: number }>(
  ({ theme, barColor, barHeight }) => ({
    height: barHeight || 8,
    borderRadius: 4,
    backgroundColor: theme.palette.grey[200],

    '& .MuiLinearProgress-bar': {
      borderRadius: 4,
      backgroundColor: barColor || theme.palette.primary.main,
      backgroundImage: `linear-gradient(90deg, ${barColor || theme.palette.primary.main} 0%, ${barColor || theme.palette.primary.light} 100%)`,
    },
  })
);

export const ProgressBar: React.FC<ProgressBarProps> = ({
  current,
  total,
  percentage,
  label,
  showPercentage = true,
  showCount = true,
  color,
  height = 8,
}) => {
  return (
    <Box sx={{ width: '100%' }}>
      {/* Label and count */}
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          mb: 1,
        }}
      >
        {label && (
          <Typography variant="body2" fontWeight={600}>
            {label}
          </Typography>
        )}

        <Typography variant="body2" color="text.secondary">
          {showPercentage && `${Math.round(percentage)}%`}
          {showPercentage && showCount && ' '}
          {showCount && `(${current} of ${total})`}
        </Typography>
      </Box>

      {/* Progress bar */}
      <StyledLinearProgress
        variant="determinate"
        value={percentage}
        barColor={color}
        barHeight={height}
      />
    </Box>
  );
};
```

#### Usage Examples

```tsx
// Assessment progress
<ProgressBar
  current={18}
  total={40}
  percentage={45}
  label="Progress"
  showPercentage
  showCount
/>

// Phase score
<ProgressBar
  current={70}
  total={100}
  percentage={70}
  label="Stabilize"
  color="#D32F2F"
  showPercentage
  showCount={false}
/>

// Simple progress
<ProgressBar
  current={3}
  total={5}
  percentage={60}
  showPercentage
  showCount
/>
```

---

## Implementation Examples

### Example: Create Assessment Form

```tsx
import React, { useState } from 'react';
import { Box } from '@mui/material';
import { Modal } from '../components/common/Modal/Modal';
import { TextField } from '../components/forms/TextField/TextField';
import { Button } from '../components/common/Button/Button';

interface CreateAssessmentFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: AssessmentData) => Promise<void>;
}

interface AssessmentData {
  clientName: string;
  businessName: string;
  email: string;
  phone?: string;
}

export const CreateAssessmentForm: React.FC<CreateAssessmentFormProps> = ({
  open,
  onClose,
  onSubmit,
}) => {
  const [formData, setFormData] = useState<AssessmentData>({
    clientName: '',
    businessName: '',
    email: '',
    phone: '',
  });

  const [errors, setErrors] = useState<Partial<AssessmentData>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const validate = (): boolean => {
    const newErrors: Partial<AssessmentData> = {};

    if (!formData.clientName.trim()) {
      newErrors.clientName = 'Client name is required';
    }

    if (!formData.businessName.trim()) {
      newErrors.businessName = 'Business name is required';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) {
      return;
    }

    setIsSubmitting(true);
    try {
      await onSubmit(formData);
      onClose();
      // Reset form
      setFormData({
        clientName: '',
        businessName: '',
        email: '',
        phone: '',
      });
    } catch (error) {
      console.error('Failed to create assessment:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create New Assessment"
      maxWidth="md"
      actions={
        <>
          <Button variant="text" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            loading={isSubmitting}
          >
            Create
          </Button>
        </>
      }
    >
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <TextField
          label="Client Name"
          value={formData.clientName}
          onChange={(e) => setFormData({ ...formData, clientName: e.target.value })}
          error={Boolean(errors.clientName)}
          errorText={errors.clientName}
          required
          fullWidth
        />

        <TextField
          label="Business Name"
          value={formData.businessName}
          onChange={(e) => setFormData({ ...formData, businessName: e.target.value })}
          error={Boolean(errors.businessName)}
          errorText={errors.businessName}
          required
          fullWidth
        />

        <TextField
          label="Email Address"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          error={Boolean(errors.email)}
          errorText={errors.email}
          helperText="Report will be sent to this email"
          required
          fullWidth
        />

        <TextField
          label="Phone"
          type="tel"
          value={formData.phone}
          onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
          helperText="Optional"
          fullWidth
        />
      </Box>
    </Modal>
  );
};
```

---

## Testing Guidelines

### Component Testing with Jest + React Testing Library

```tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Button } from './Button';

describe('Button Component', () => {
  it('renders children correctly', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);

    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('does not call onClick when disabled', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick} disabled>Click me</Button>);

    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).not.toHaveBeenCalled();
  });

  it('shows loading spinner when loading', () => {
    render(<Button loading>Click me</Button>);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('is disabled when loading', () => {
    render(<Button loading>Click me</Button>);
    expect(screen.getByRole('button')).toBeDisabled();
  });
});
```

---

**Document Version:** 1.0
**Last Updated:** 2025-12-19
**Maintained by:** Frontend Development Team

For related documentation, refer to:
- Design System: `docs/design-system.md`
- Wireframes: `docs/wireframes.md`
- Requirements: `plans/requirements.md`
