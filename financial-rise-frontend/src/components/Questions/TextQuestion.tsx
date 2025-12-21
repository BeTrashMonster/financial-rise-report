import React from 'react';
import { FormControl, FormLabel, TextField, FormHelperText } from '@mui/material';
import type { Question } from '@/types';

interface TextQuestionProps {
  question: Question;
  value: string | null;
  onChange: (value: string) => void;
  disabled?: boolean;
}

/**
 * Text Input Question Component
 * REQ-QUEST-004: Text question type
 */
export const TextQuestion: React.FC<TextQuestionProps> = ({
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
      <TextField
        multiline
        rows={4}
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Enter your response..."
        inputProps={{
          maxLength: 1000,
          'aria-label': question.text,
          'aria-required': question.required,
        }}
        fullWidth
      />
      <FormHelperText>
        {question.required ? '* Required - ' : ''}Maximum 1000 characters
      </FormHelperText>
    </FormControl>
  );
};

export default TextQuestion;
