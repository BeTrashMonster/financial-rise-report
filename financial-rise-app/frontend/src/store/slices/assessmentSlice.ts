import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { assessmentService, CreateAssessmentRequest } from '@services/assessmentService';

export interface Question {
  id: string;
  text: string;
  type: 'multiple_choice' | 'scale' | 'text' | 'boolean';
  options?: string[];
  required: boolean;
  phase?: string;
}

export interface Answer {
  questionId: string;
  value: string | number | boolean;
}

export interface Assessment {
  id: string;
  clientName: string;
  status: 'draft' | 'in_progress' | 'completed';
  answers: Answer[];
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
}

export interface AssessmentState {
  currentAssessment: Assessment | null;
  assessments: Assessment[];
  questions: Question[];
  loading: boolean;
  error: string | null;
}

const initialState: AssessmentState = {
  currentAssessment: null,
  assessments: [],
  questions: [],
  loading: false,
  error: null,
};

/**
 * Async Thunks
 */
export const fetchQuestions = createAsyncThunk(
  'assessment/fetchQuestions',
  async (assessmentId: string | undefined, { rejectWithValue }) => {
    try {
      const response = await assessmentService.getQuestions(assessmentId);
      return response.questions; // Extract questions array from response
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch questions');
    }
  }
);

export const createAssessment = createAsyncThunk(
  'assessment/create',
  async (data: CreateAssessmentRequest, { rejectWithValue }) => {
    try {
      const response = await assessmentService.createAssessment(data);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.message || 'Failed to create assessment');
    }
  }
);

export const saveAnswer = createAsyncThunk(
  'assessment/saveAnswer',
  async (
    { assessmentId, answer }: { assessmentId: string; answer: Answer },
    { rejectWithValue }
  ) => {
    try {
      const response = await assessmentService.saveAnswer(assessmentId, answer);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.message || 'Failed to save answer');
    }
  }
);

export const submitAssessment = createAsyncThunk(
  'assessment/submit',
  async (assessmentId: string, { rejectWithValue }) => {
    try {
      const response = await assessmentService.submitAssessment(assessmentId);
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.message || 'Failed to submit assessment');
    }
  }
);

export const fetchAssessments = createAsyncThunk(
  'assessment/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await assessmentService.getAssessments();
      return response;
    } catch (error: any) {
      return rejectWithValue(error.response?.data?.message || 'Failed to fetch assessments');
    }
  }
);

/**
 * Assessment Slice
 */
const assessmentSlice = createSlice({
  name: 'assessment',
  initialState,
  reducers: {
    clearCurrentAssessment: (state) => {
      state.currentAssessment = null;
    },
    clearError: (state) => {
      state.error = null;
    },
    updateLocalAnswer: (state, action: PayloadAction<Answer>) => {
      if (state.currentAssessment) {
        const existingIndex = state.currentAssessment.answers.findIndex(
          (a) => a.questionId === action.payload.questionId
        );
        if (existingIndex >= 0) {
          state.currentAssessment.answers[existingIndex] = action.payload;
        } else {
          state.currentAssessment.answers.push(action.payload);
        }
      }
    },
  },
  extraReducers: (builder) => {
    // Fetch Questions
    builder
      .addCase(fetchQuestions.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchQuestions.fulfilled, (state, action: PayloadAction<Question[]>) => {
        state.loading = false;
        state.questions = action.payload;
      })
      .addCase(fetchQuestions.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });

    // Create Assessment
    builder
      .addCase(createAssessment.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createAssessment.fulfilled, (state, action: PayloadAction<Assessment>) => {
        state.loading = false;
        state.currentAssessment = action.payload;
        state.assessments.push(action.payload);
      })
      .addCase(createAssessment.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });

    // Save Answer
    builder
      .addCase(saveAnswer.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(saveAnswer.fulfilled, (state, action: PayloadAction<Assessment>) => {
        state.loading = false;
        state.currentAssessment = action.payload;
      })
      .addCase(saveAnswer.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });

    // Submit Assessment
    builder
      .addCase(submitAssessment.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(submitAssessment.fulfilled, (state, action: PayloadAction<Assessment>) => {
        state.loading = false;
        state.currentAssessment = action.payload;
        const index = state.assessments.findIndex((a) => a.id === action.payload.id);
        if (index >= 0) {
          state.assessments[index] = action.payload;
        }
      })
      .addCase(submitAssessment.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });

    // Fetch Assessments
    builder
      .addCase(fetchAssessments.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAssessments.fulfilled, (state, action: PayloadAction<Assessment[]>) => {
        state.loading = false;
        state.assessments = action.payload;
      })
      .addCase(fetchAssessments.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload as string;
      });
  },
});

export const { clearCurrentAssessment, clearError, updateLocalAnswer } = assessmentSlice.actions;
export default assessmentSlice.reducer;
