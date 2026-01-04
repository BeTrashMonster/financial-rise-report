/**
 * Assessment List Page
 * Work Stream 1: Assessment List Page
 *
 * Displays all assessments for the logged-in consultant with:
 * - Filtering by status and phase
 * - Search functionality
 * - Sorting capabilities
 * - Responsive table/card layout
 * - "New Assessment" button
 * - WCAG 2.1 AA accessibility compliance
 */

import React, { useEffect, useState, useMemo } from 'react';
import {
  Box,
  Container,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Paper,
  Chip,
  IconButton,
  Grid,
  InputAdornment,
  Alert,
  CircularProgress,
  useTheme,
  useMediaQuery,
  SelectChangeEvent,
} from '@mui/material';
import {
  Add as AddIcon,
  Search as SearchIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { fetchAssessments } from '@store/slices/assessmentSlice';
import type { Assessment } from '@store/slices/assessmentSlice';
import { Card } from '@components/common/Card/Card';

type SortField = 'clientName' | 'status' | 'createdAt' | 'updatedAt';
type SortOrder = 'asc' | 'desc';
type StatusFilter = 'all' | 'draft' | 'in_progress' | 'completed';

/**
 * Get color for assessment status chip
 */
const getStatusColor = (
  status: Assessment['status']
): 'default' | 'primary' | 'success' | 'warning' => {
  switch (status) {
    case 'completed':
      return 'success';
    case 'in_progress':
      return 'primary';
    case 'draft':
      return 'warning';
    default:
      return 'default';
  }
};

/**
 * Format date to locale string
 */
const formatDate = (dateString: string): string => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};

/**
 * Assessment List Component
 */
export const AssessmentList: React.FC = () => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const { assessments, loading, error } = useAppSelector((state) => state.assessment);

  // Filter and sort state
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [sortField, setSortField] = useState<SortField>('updatedAt');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  // Fetch assessments on mount
  useEffect(() => {
    dispatch(fetchAssessments());
  }, [dispatch]);

  // Filter and sort assessments
  const filteredAndSortedAssessments = useMemo(() => {
    let filtered = [...assessments];

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter((assessment) =>
        assessment.clientName.toLowerCase().includes(query)
      );
    }

    // Apply status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter((assessment) => assessment.status === statusFilter);
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let compareValue = 0;

      switch (sortField) {
        case 'clientName':
          compareValue = a.clientName.localeCompare(b.clientName);
          break;
        case 'status':
          compareValue = a.status.localeCompare(b.status);
          break;
        case 'createdAt':
          compareValue = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
          break;
        case 'updatedAt':
          compareValue = new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime();
          break;
      }

      return sortOrder === 'asc' ? compareValue : -compareValue;
    });

    return filtered;
  }, [assessments, searchQuery, statusFilter, sortField, sortOrder]);

  // Handle sort change
  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  // Handle filter changes
  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  };

  const handleStatusFilterChange = (event: SelectChangeEvent<StatusFilter>) => {
    setStatusFilter(event.target.value as StatusFilter);
  };

  // Handle actions
  const handleNewAssessment = () => {
    navigate('/assessments/new');
  };

  const handleViewAssessment = (id: string) => {
    navigate(`/assessments/${id}`);
  };

  const handleEditAssessment = (id: string) => {
    navigate(`/assessments/${id}/edit`);
  };

  const handleRefresh = () => {
    dispatch(fetchAssessments());
  };

  // Desktop table view
  const renderTableView = () => (
    <TableContainer component={Paper}>
      <Table aria-label="assessment list table">
        <TableHead>
          <TableRow>
            <TableCell>
              <TableSortLabel
                active={sortField === 'clientName'}
                direction={sortField === 'clientName' ? sortOrder : 'asc'}
                onClick={() => handleSort('clientName')}
              >
                Client Name
              </TableSortLabel>
            </TableCell>
            <TableCell>
              <TableSortLabel
                active={sortField === 'status'}
                direction={sortField === 'status' ? sortOrder : 'asc'}
                onClick={() => handleSort('status')}
              >
                Status
              </TableSortLabel>
            </TableCell>
            <TableCell>
              <TableSortLabel
                active={sortField === 'createdAt'}
                direction={sortField === 'createdAt' ? sortOrder : 'asc'}
                onClick={() => handleSort('createdAt')}
              >
                Created
              </TableSortLabel>
            </TableCell>
            <TableCell>
              <TableSortLabel
                active={sortField === 'updatedAt'}
                direction={sortField === 'updatedAt' ? sortOrder : 'asc'}
                onClick={() => handleSort('updatedAt')}
              >
                Last Updated
              </TableSortLabel>
            </TableCell>
            <TableCell align="right">Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {filteredAndSortedAssessments.length === 0 ? (
            <TableRow>
              <TableCell colSpan={5} align="center">
                <Typography variant="body2" color="text.secondary" sx={{ py: 4 }}>
                  {searchQuery || statusFilter !== 'all'
                    ? 'No assessments match your filters'
                    : 'No assessments yet. Create your first assessment to get started.'}
                </Typography>
              </TableCell>
            </TableRow>
          ) : (
            filteredAndSortedAssessments.map((assessment) => (
              <TableRow
                key={assessment.id}
                hover
                sx={{ '&:hover': { cursor: 'pointer' } }}
                onClick={() => handleViewAssessment(assessment.id)}
              >
                <TableCell>
                  <Typography variant="body2" fontWeight={500}>
                    {assessment.clientName}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={assessment.status.replace('_', ' ').toUpperCase()}
                    color={getStatusColor(assessment.status)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {formatDate(assessment.createdAt)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {formatDate(assessment.updatedAt)}
                  </Typography>
                </TableCell>
                <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                  <IconButton
                    size="small"
                    onClick={() => handleViewAssessment(assessment.id)}
                    aria-label={`View assessment for ${assessment.clientName}`}
                    sx={{ mr: 1 }}
                  >
                    <ViewIcon fontSize="small" />
                  </IconButton>
                  {assessment.status !== 'completed' && (
                    <IconButton
                      size="small"
                      onClick={() => handleEditAssessment(assessment.id)}
                      aria-label={`Edit assessment for ${assessment.clientName}`}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                  )}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </TableContainer>
  );

  // Mobile card view
  const renderCardView = () => (
    <Grid container spacing={2}>
      {filteredAndSortedAssessments.length === 0 ? (
        <Grid item xs={12}>
          <Card>
            <Typography variant="body2" color="text.secondary" align="center">
              {searchQuery || statusFilter !== 'all'
                ? 'No assessments match your filters'
                : 'No assessments yet. Create your first assessment to get started.'}
            </Typography>
          </Card>
        </Grid>
      ) : (
        filteredAndSortedAssessments.map((assessment) => (
          <Grid item xs={12} key={assessment.id}>
            <Card
              sx={{
                '&:hover': {
                  cursor: 'pointer',
                  boxShadow: theme.shadows[4],
                },
              }}
              onClick={() => handleViewAssessment(assessment.id)}
            >
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6" component="h3" gutterBottom>
                    {assessment.clientName}
                  </Typography>
                  <Chip
                    label={assessment.status.replace('_', ' ').toUpperCase()}
                    color={getStatusColor(assessment.status)}
                    size="small"
                    sx={{ mb: 1 }}
                  />
                  <Typography variant="body2" color="text.secondary">
                    Created: {formatDate(assessment.createdAt)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Updated: {formatDate(assessment.updatedAt)}
                  </Typography>
                </Box>
                <Box onClick={(e) => e.stopPropagation()}>
                  <IconButton
                    size="small"
                    onClick={() => handleViewAssessment(assessment.id)}
                    aria-label={`View assessment for ${assessment.clientName}`}
                  >
                    <ViewIcon fontSize="small" />
                  </IconButton>
                  {assessment.status !== 'completed' && (
                    <IconButton
                      size="small"
                      onClick={() => handleEditAssessment(assessment.id)}
                      aria-label={`Edit assessment for ${assessment.clientName}`}
                    >
                      <EditIcon fontSize="small" />
                    </IconButton>
                  )}
                </Box>
              </Box>
            </Card>
          </Grid>
        ))
      )}
    </Grid>
  );

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Assessments
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Manage your client financial readiness assessments
        </Typography>
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => dispatch(fetchAssessments())}>
          {error}
        </Alert>
      )}

      {/* Filters and Actions */}
      <Box sx={{ mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          {/* Search */}
          <Grid item xs={12} sm={6} md={4}>
            <TextField
              fullWidth
              placeholder="Search by client name..."
              value={searchQuery}
              onChange={handleSearchChange}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              aria-label="Search assessments by client name"
            />
          </Grid>

          {/* Status Filter */}
          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth>
              <InputLabel id="status-filter-label">Status</InputLabel>
              <Select
                labelId="status-filter-label"
                id="status-filter"
                value={statusFilter}
                label="Status"
                onChange={handleStatusFilterChange}
                aria-label="Filter assessments by status"
              >
                <MenuItem value="all">All Status</MenuItem>
                <MenuItem value="draft">Draft</MenuItem>
                <MenuItem value="in_progress">In Progress</MenuItem>
                <MenuItem value="completed">Completed</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          {/* Actions */}
          <Grid item xs={12} md={5} sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={handleRefresh}
              disabled={loading}
              aria-label="Refresh assessments list"
            >
              Refresh
            </Button>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleNewAssessment}
              aria-label="Create new assessment"
            >
              New Assessment
            </Button>
          </Grid>
        </Grid>
      </Box>

      {/* Results Count */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Showing {filteredAndSortedAssessments.length} of {assessments.length} assessments
        </Typography>
      </Box>

      {/* Loading State */}
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
          <CircularProgress aria-label="Loading assessments" />
        </Box>
      ) : (
        /* Responsive View */
        isMobile ? renderCardView() : renderTableView()
      )}
    </Container>
  );
};

export default AssessmentList;
