import React from 'react';
import {
  FormControl,
  FormLabel,
  Rating,
  Box,
  Typography,
  FormHelperText,
} from '@mui/material';
import type { Question } from '@/types';

interface RatingQuestionProps {
  question: Question;
  value: number | null;
  onChange: (value: number) => void;
  disabled?: boolean;
}

/**
 * Rating Question Component (1-5 scale)
 * REQ-QUEST-004: Rating question type
 */
export const RatingQuestion: React.FC<RatingQuestionProps> = ({
  question,
  value,
  onChange,
  disabled = false,
}) => {
  return (
    <FormControl component="fieldset" fullWidth disabled={disabled}>
      <FormLabel component="legend" required={question.required} sx={{ mb: 2 }}>
        {question.text}
      </FormLabel>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Rating
          value={value || 0}
          onChange={(event, newValue) => {
            if (newValue !== null) {
              onChange(newValue);
            }
          }}
          size="large"
          max={5}
          aria-label={question.text}
        />
        {value && (
          <Typography variant="body1" color="text.secondary">
            {value} / 5
          </Typography>
        )}
      </Box>
      {question.required && (
        <FormHelperText>* Required</FormHelperText>
      )}
    </FormControl>
  );
};

export default RatingQuestion;
