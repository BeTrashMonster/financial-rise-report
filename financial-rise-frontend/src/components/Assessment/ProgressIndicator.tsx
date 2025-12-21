import React from 'react';
import { Box, LinearProgress, Typography } from '@mui/material';

interface ProgressIndicatorProps {
  progress: number;
  showLabel?: boolean;
}

/**
 * Progress indicator component
 * REQ-ASSESS-006: Display progress percentage
 * REQ-UI-006: Loading indicators
 */
export const ProgressIndicator: React.FC<ProgressIndicatorProps> = ({
  progress,
  showLabel = true,
}) => {
  return (
    <Box sx={{ width: '100%' }}>
      {showLabel && (
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Assessment Progress
          </Typography>
          <Typography variant="body2" color="text.secondary" fontWeight="600">
            {Math.round(progress)}%
          </Typography>
        </Box>
      )}
      <LinearProgress
        variant="determinate"
        value={progress}
        sx={{
          height: 8,
          borderRadius: 4,
          bgcolor: 'grey.200',
          '& .MuiLinearProgress-bar': {
            borderRadius: 4,
            bgcolor: progress === 100 ? 'success.main' : 'primary.main',
          },
        }}
        aria-label={`Assessment ${Math.round(progress)}% complete`}
      />
    </Box>
  );
};

export default ProgressIndicator;
