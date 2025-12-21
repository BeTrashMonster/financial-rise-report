import React from 'react';
import {
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  FormHelperText,
  Box,
} from '@mui/material';
import type { Question, QuestionOption } from '@/types';

interface SingleChoiceQuestionProps {
  question: Question;
  value: string | null;
  onChange: (value: string) => void;
  disabled?: boolean;
}

/**
 * Single Choice Question Component
 * REQ-QUEST-004: Single choice question type
 */
export const SingleChoiceQuestion: React.FC<SingleChoiceQuestionProps> = ({
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
      <RadioGroup
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        aria-label={question.text}
      >
        {question.options?.map((option: QuestionOption) => (
          <FormControlLabel
            key={option.optionId}
            value={option.optionId}
            control={<Radio />}
            label={option.text}
          />
        ))}
      </RadioGroup>
      {question.required && (
        <FormHelperText>* Required</FormHelperText>
      )}
    </FormControl>
  );
};

export default SingleChoiceQuestion;
