# Dashboard Enhancements Frontend - Technical Specification

**Version:** 1.0
**Date:** 2025-12-22
**Work Stream:** 32 - Dashboard Enhancements Frontend
**Phase:** 2 - Enhanced Engagement
**Dependency Level:** 1

## Overview

The Dashboard Enhancements Frontend provides consultants with powerful tools to filter, search, and manage large numbers of assessments efficiently.

### Key Features

1. **Advanced Filtering** - Multi-criteria filtering (status, date range, client name)
2. **Full-Text Search** - Fast search with auto-complete
3. **Archive Management** - Archive/restore assessments with bulk operations
4. **Assessment Statistics** - Visual metrics and completion tracking
5. **Responsive Data Table** - Mobile-friendly card layout

## Component Architecture

```
EnhancedDashboard
├── DashboardHeader
│   ├── WelcomeMessage
│   └── QuickStats
├── FilterBar
│   ├── StatusFilter
│   ├── DateRangeFilter
│   ├── ClientNameFilter
│   └── ClearFiltersButton
├── SearchBar
│   ├── SearchInput (with autocomplete)
│   └── SearchResults
├── AssessmentTable
│   ├── TableToolbar
│   │   ├── BulkActions
│   │   └── ViewToggle (table/cards)
│   ├── AssessmentTableView
│   │   └── AssessmentRow (x N)
│   └── AssessmentCardsView
│       └── AssessmentCard (x N)
├── ArchiveDrawer
│   └── ArchivedAssessmentsList
└── Pagination
```

## UI Design - Filter Bar

```
┌──────────────────────────────────────────────────────────────┐
│  Dashboard                                                    │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                │
│  Welcome back, Jane!                                          │
│  You have 47 assessments (12 in progress, 30 completed)       │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│  Filters:                                                      │
│  ┌──────────┐ ┌─────────────┐ ┌──────────┐ ┌────────┐        │
│  │ Status ▼ │ │ Date Range ▼│ │ Client   │ │ Clear  │        │
│  └──────────┘ └─────────────┘ └──────────┘ └────────┘        │
│                                                                │
│  Search: ┌────────────────────────────────────────────┐       │
│          │ 🔍 Search by client or business name...    │       │
│          └────────────────────────────────────────────┘       │
│                                                                │
├────────────────────────────────────────────────────────────────┤
│  Showing 12 of 47 assessments  [Archive] [⊞ Table] [▦ Cards]  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│                                                                │
│  □  John Smith · ABC Corp              In Progress  68%  [⋮]  │
│      Created: Dec 15 • Last activity: 2 hours ago             │
│                                                                │
│  □  Jane Doe · XYZ Enterprises         Completed   100%  [⋮]  │
│      Created: Dec 10 • Completed: Dec 18                      │
│                                                                │
│  □  Bob Johnson · Tech Startup         Draft       0%    [⋮]  │
│      Created: Dec 20 • Not started                            │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Implementation

### Filter Hook

```typescript
export function useAssessmentFilters() {
  const [filters, setFilters] = useState({
    status: null,
    start_date: null,
    end_date: null,
    client_name: '',
    search: '',
    archived: false
  });

  const updateFilter = useCallback((key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  }, []);

  const clearFilters = useCallback(() => {
    setFilters({
      status: null,
      start_date: null,
      end_date: null,
      client_name: '',
      search: '',
      archived: false
    });
  }, []);

  return { filters, updateFilter, clearFilters };
}
```

### Search with Autocomplete

```typescript
export function SearchBar() {
  const [query, setQuery] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const { searchAssessments } = useAssessmentApi();

  const debouncedSearch = useMemo(
    () => debounce(async (q) => {
      if (q.length >= 2) {
        const results = await searchAssessments(q);
        setSuggestions(results);
      }
    }, 300),
    []
  );

  useEffect(() => {
    debouncedSearch(query);
  }, [query, debouncedSearch]);

  return (
    <Autocomplete
      freeSolo
      options={suggestions}
      getOptionLabel={(option) => option.business_name || option.client_name}
      onInputChange={(e, value) => setQuery(value)}
      renderInput={(params) => (
        <TextField
          {...params}
          placeholder="Search by client or business name..."
          InputProps={{
            ...params.InputProps,
            startAdornment: <SearchIcon />
          }}
        />
      )}
      renderOption={(props, option) => (
        <ListItem {...props}>
          <ListItemText
            primary={option.business_name}
            secondary={option.client_name}
          />
          <Chip label={option.status} size="small" />
        </ListItem>
      )}
    />
  );
}
```

### Bulk Archive

```typescript
export function BulkActions({ selectedIds }) {
  const { bulkArchive } = useAssessmentApi();
  const [isArchiving, setIsArchiving] = useState(false);

  const handleBulkArchive = async () => {
    if (!confirm(`Archive ${selectedIds.length} assessments?`)) return;

    setIsArchiving(true);
    try {
      await bulkArchive(selectedIds);
      showToast(`Archived ${selectedIds.length} assessments`);
    } catch (error) {
      showToast('Failed to archive assessments', 'error');
    } finally {
      setIsArchiving(false);
    }
  };

  return (
    <Button
      onClick={handleBulkArchive}
      disabled={selectedIds.length === 0 || isArchiving}
      startIcon={<ArchiveIcon />}
    >
      Archive {selectedIds.length} Selected
    </Button>
  );
}
```

## Testing

```typescript
test('filters assessments by status', async ({ page }) => {
  await page.goto('/dashboard');

  await page.selectOption('select[name="status"]', 'Completed');
  
  await page.waitForLoadState('networkidle');
  
  const rows = await page.locator('.assessment-row').all();
  for (const row of rows) {
    await expect(row.locator('.status-badge')).toContainText('Completed');
  }
});

test('searches assessments', async ({ page }) => {
  await page.goto('/dashboard');

  await page.fill('input[placeholder*="Search"]', 'ABC Corp');
  
  await expect(page.locator('.assessment-row >> text=ABC Corp')).toBeVisible();
});
```

---

**Document Version:** 1.0
**Author:** Frontend Developer 1
**Last Updated:** 2025-12-22
**Status:** Ready for Implementation
