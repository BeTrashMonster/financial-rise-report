import React from 'react';
import { Box, Chip, CircularProgress } from '@mui/material';
import { Check as CheckIcon, CloudOff as UnsavedIcon } from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

interface AutoSaveIndicatorProps {
  isSaving: boolean;
  isDirty: boolean;
  lastSavedAt: Date | null;
}

/**
 * Auto-save status indicator
 * REQ-ASSESS-005: Auto-save functionality
 * REQ-UI-006: Loading indicators
 */
export const AutoSaveIndicator: React.FC<AutoSaveIndicatorProps> = ({
  isSaving,
  isDirty,
  lastSavedAt,
}) => {
  if (isSaving) {
    return (
      <Chip
        icon={<CircularProgress size={16} sx={{ color: 'inherit' }} />}
        label="Saving..."
        color="primary"
        size="small"
        variant="outlined"
        aria-live="polite"
        aria-label="Saving changes"
      />
    );
  }

  if (isDirty) {
    return (
      <Chip
        icon={<UnsavedIcon />}
        label="Unsaved changes"
        color="warning"
        size="small"
        variant="outlined"
        aria-live="polite"
        aria-label="You have unsaved changes"
      />
    );
  }

  if (lastSavedAt) {
    return (
      <Chip
        icon={<CheckIcon />}
        label={`Saved ${formatDistanceToNow(lastSavedAt, { addSuffix: true })}`}
        color="success"
        size="small"
        variant="outlined"
        aria-live="polite"
        aria-label={`Changes saved ${formatDistanceToNow(lastSavedAt, { addSuffix: true })}`}
      />
    );
  }

  return null;
};

export default AutoSaveIndicator;
