import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Grid,
  CircularProgress,
  Alert,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { AppLayout } from '@/components/Layout/AppLayout';
import { AssessmentCard } from '@/components/Assessment/AssessmentCard';
import { apiService } from '@/services/api';
import { useAssessmentStore } from '@/store/assessmentStore';
import type { Assessment, AssessmentStatus } from '@/types';

/**
 * Dashboard Page
 * Lists all assessments for the consultant
 * REQ-ASSESS-004: Resume in-progress assessments
 */
export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { assessments, setAssessments, removeAssessment } = useAssessmentStore();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadAssessments();
  }, [statusFilter]);

  const loadAssessments = async () => {
    try {
      setLoading(true);
      setError(null);
      const params: any = {
        sortBy: 'updatedAt',
        sortOrder: 'desc',
      };
      if (statusFilter !== 'all') {
        params.status = statusFilter;
      }
      const response = await apiService.listAssessments(params);
      setAssessments(response.assessments);
    } catch (err: any) {
      setError(err.response?.data?.error?.message || 'Failed to load assessments');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNew = () => {
    navigate('/assessment/create');
  };

  const handleEditAssessment = (assessmentId: string) => {
    navigate(`/assessment/${assessmentId}`);
  };

  const handleDeleteAssessment = async (assessmentId: string) => {
    if (!window.confirm('Are you sure you want to delete this draft assessment?')) {
      return;
    }

    try {
      await apiService.deleteAssessment(assessmentId);
      removeAssessment(assessmentId);
    } catch (err: any) {
      alert(err.response?.data?.error?.message || 'Failed to delete assessment');
    }
  };

  const handleViewReports = (assessmentId: string) => {
    navigate(`/reports/${assessmentId}`);
  };

  const filteredAssessments = assessments.filter((assessment) => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        assessment.clientName.toLowerCase().includes(query) ||
        assessment.businessName.toLowerCase().includes(query)
      );
    }
    return true;
  });

  return (
    <AppLayout>
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4" component="h1">
            Assessments
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleCreateNew}
            size="large"
            aria-label="Create new assessment"
          >
            New Assessment
          </Button>
        </Box>

        {/* Filters */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
          <TextField
            label="Search"
            variant="outlined"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by client or business name..."
            sx={{ flex: 1 }}
            aria-label="Search assessments"
          />
          <FormControl sx={{ minWidth: 200 }}>
            <InputLabel id="status-filter-label">Status</InputLabel>
            <Select
              labelId="status-filter-label"
              id="status-filter"
              value={statusFilter}
              label="Status"
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter by status"
            >
              <MenuItem value="all">All</MenuItem>
              <MenuItem value="draft">Draft</MenuItem>
              <MenuItem value="in_progress">In Progress</MenuItem>
              <MenuItem value="completed">Completed</MenuItem>
            </Select>
          </FormControl>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Loading State */}
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <CircularProgress />
          </Box>
        )}

        {/* Empty State */}
        {!loading && filteredAssessments.length === 0 && (
          <Box sx={{ textAlign: 'center', py: 8 }}>
            <Typography variant="h6" color="text.secondary" gutterBottom>
              {searchQuery || statusFilter !== 'all' ? 'No assessments found' : 'No assessments yet'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              {searchQuery || statusFilter !== 'all'
                ? 'Try adjusting your filters'
                : 'Get started by creating your first assessment'}
            </Typography>
            {!searchQuery && statusFilter === 'all' && (
              <Button variant="contained" startIcon={<AddIcon />} onClick={handleCreateNew}>
                Create Your First Assessment
              </Button>
            )}
          </Box>
        )}

        {/* Assessment Grid */}
        {!loading && filteredAssessments.length > 0 && (
          <Grid container spacing={3}>
            {filteredAssessments.map((assessment) => (
              <Grid item xs={12} sm={6} md={4} key={assessment.assessmentId}>
                <AssessmentCard
                  assessment={assessment}
                  onEdit={handleEditAssessment}
                  onDelete={handleDeleteAssessment}
                  onViewReports={handleViewReports}
                />
              </Grid>
            ))}
          </Grid>
        )}
      </Box>
    </AppLayout>
  );
};

export default Dashboard;
