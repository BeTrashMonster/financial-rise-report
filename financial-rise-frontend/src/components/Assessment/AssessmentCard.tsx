import React from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Button,
  Box,
  IconButton,
  Tooltip,
  Stack,
} from '@mui/material';
import {
  Edit as EditIcon,
  Delete as DeleteIcon,
  CheckCircle as CompleteIcon,
  RadioButtonUnchecked as DraftIcon,
  PlayArrow as InProgressIcon,
  Description as ReportIcon,
} from '@mui/icons-material';
import { format } from 'date-fns';
import { Assessment, AssessmentStatus } from '@/types';
import { ProgressIndicator } from './ProgressIndicator';

interface AssessmentCardProps {
  assessment: Assessment;
  onEdit: (assessmentId: string) => void;
  onDelete: (assessmentId: string) => void;
  onViewReports?: (assessmentId: string) => void;
}

/**
 * Assessment card for dashboard list
 * REQ-UI-004: Clear visual hierarchy
 */
export const AssessmentCard: React.FC<AssessmentCardProps> = ({
  assessment,
  onEdit,
  onDelete,
  onViewReports,
}) => {
  const getStatusIcon = (status: AssessmentStatus) => {
    switch (status) {
      case AssessmentStatus.DRAFT:
        return <DraftIcon fontSize="small" />;
      case AssessmentStatus.IN_PROGRESS:
        return <InProgressIcon fontSize="small" />;
      case AssessmentStatus.COMPLETED:
        return <CompleteIcon fontSize="small" />;
    }
  };

  const getStatusColor = (status: AssessmentStatus) => {
    switch (status) {
      case AssessmentStatus.DRAFT:
        return 'default';
      case AssessmentStatus.IN_PROGRESS:
        return 'primary';
      case AssessmentStatus.COMPLETED:
        return 'success';
    }
  };

  const getStatusLabel = (status: AssessmentStatus) => {
    switch (status) {
      case AssessmentStatus.DRAFT:
        return 'Draft';
      case AssessmentStatus.IN_PROGRESS:
        return 'In Progress';
      case AssessmentStatus.COMPLETED:
        return 'Completed';
    }
  };

  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        transition: 'transform 0.2s, box-shadow 0.2s',
        '&:hover': {
          transform: 'translateY(-4px)',
          boxShadow: '0 4px 12px rgba(75, 0, 110, 0.15)',
        },
      }}
    >
      <CardContent sx={{ flexGrow: 1 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', mb: 2 }}>
          <Typography variant="h6" component="h2" sx={{ fontWeight: 600 }}>
            {assessment.businessName}
          </Typography>
          <Chip
            icon={getStatusIcon(assessment.status)}
            label={getStatusLabel(assessment.status)}
            color={getStatusColor(assessment.status)}
            size="small"
          />
        </Box>

        <Typography variant="body1" color="text.secondary" gutterBottom>
          {assessment.clientName}
        </Typography>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Updated {format(new Date(assessment.updatedAt), 'MMM d, yyyy')}
        </Typography>

        <ProgressIndicator progress={assessment.progress} />
      </CardContent>

      <CardActions sx={{ justifyContent: 'space-between', px: 2, pb: 2 }}>
        <Stack direction="row" spacing={1} sx={{ flex: 1 }}>
          <Button
            variant="contained"
            startIcon={<EditIcon />}
            onClick={() => onEdit(assessment.assessmentId)}
            aria-label={`Edit assessment for ${assessment.businessName}`}
          >
            {assessment.status === AssessmentStatus.COMPLETED ? 'View' : 'Continue'}
          </Button>

          {assessment.status === AssessmentStatus.COMPLETED && onViewReports && (
            <Button
              variant="outlined"
              startIcon={<ReportIcon />}
              onClick={() => onViewReports(assessment.assessmentId)}
              aria-label={`View reports for ${assessment.businessName}`}
            >
              Reports
            </Button>
          )}
        </Stack>

        {assessment.status === AssessmentStatus.DRAFT && (
          <Tooltip title="Delete draft">
            <IconButton
              color="error"
              onClick={() => onDelete(assessment.assessmentId)}
              size="small"
              aria-label={`Delete draft assessment for ${assessment.businessName}`}
            >
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        )}
      </CardActions>
    </Card>
  );
};

export default AssessmentCard;
