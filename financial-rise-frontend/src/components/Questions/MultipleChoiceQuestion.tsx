import React from 'react';
import {
  FormControl,
  FormLabel,
  FormGroup,
  FormControlLabel,
  Checkbox,
  FormHelperText,
} from '@mui/material';
import type { Question, QuestionOption } from '@/types';

interface MultipleChoiceQuestionProps {
  question: Question;
  value: string[] | null;
  onChange: (value: string[]) => void;
  disabled?: boolean;
}

/**
 * Multiple Choice Question Component
 * REQ-QUEST-004: Multiple choice question type
 */
export const MultipleChoiceQuestion: React.FC<MultipleChoiceQuestionProps> = ({
  question,
  value,
  onChange,
  disabled = false,
}) => {
  const selectedValues = value || [];

  const handleChange = (optionId: string, checked: boolean) => {
    if (checked) {
      onChange([...selectedValues, optionId]);
    } else {
      onChange(selectedValues.filter((id) => id !== optionId));
    }
  };

  return (
    <FormControl component="fieldset" fullWidth disabled={disabled}>
      <FormLabel component="legend" required={question.required} sx={{ mb: 2 }}>
        {question.text}
      </FormLabel>
      <FormGroup>
        {question.options?.map((option: QuestionOption) => (
          <FormControlLabel
            key={option.optionId}
            control={
              <Checkbox
                checked={selectedValues.includes(option.optionId)}
                onChange={(e) => handleChange(option.optionId, e.target.checked)}
              />
            }
            label={option.text}
          />
        ))}
      </FormGroup>
      {question.required && (
        <FormHelperText>* Required - Select at least one option</FormHelperText>
      )}
    </FormControl>
  );
};

export default MultipleChoiceQuestion;
