# Quick Start Guide - Questionnaire UI with Mock API

## Get Started in 3 Steps

### Step 1: Install Dependencies
```bash
cd financial-rise-frontend
npm install
```

### Step 2: Start Development Server
```bash
npm run dev
```

The app will start at `http://localhost:5173`

### Step 3: Test the Questionnaire

Navigate to either of these mock assessments:

**Assessment 1 (In Progress - 44% complete):**
```
http://localhost:5173/questionnaire/a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
```
- Client: John Smith / Acme Corp
- 4 out of 9 questions already answered
- Has consultant notes
- See progress tracking and existing responses

**Assessment 2 (Draft - 0% complete):**
```
http://localhost:5173/questionnaire/b2c3d4e5-f6a7-5b6c-9d0e-1f2a3b4c5d6e
```
- Client: Jane Doe / Tech Startup LLC
- Fresh assessment
- Start from question 1

## What You'll See

### Question Types Demonstrated:

1. **Single Choice (Radio Buttons)**
   - Example: "How frequently do you review financial statements?"
   - Options: Weekly, Monthly, Quarterly, Annually

2. **Multiple Choice (Checkboxes)**
   - Example: "Which accounting systems do you use?"
   - Options: QuickBooks, Xero, FreshBooks, Spreadsheet, None

3. **Rating (1-5 Stars)**
   - Example: "How well do you understand tax obligations?"
   - Interactive star rating component

4. **Text Input (Free Form)**
   - Example: "Additional financial challenges?"
   - Multiline text area with character limit

### Features to Test:

- **Navigation**: Previous/Next buttons
- **Progress**: Watch percentage update as you answer
- **Not Applicable**: Checkbox to mark question as N/A (disables input)
- **Consultant Notes**: Private notes field below each question
- **Auto-Save**: Watch console logs - saves every 30 seconds when dirty
- **Complete**: Finish all 9 questions to complete assessment

## Mock Data Structure

### All 9 Questions:

1. FIN-001 (Stabilize): Financial statement review frequency
2. FIN-002 (Stabilize): Chart of accounts documentation
3. FIN-003 (Stabilize): Tax obligations understanding (rating)
4. FIN-004 (Organize): Budget existence
5. FIN-005 (Organize): Accounting systems (multiple choice)
6. FIN-006 (Build): Financial processes documentation
7. FIN-007 (Grow): Financial projections
8. FIN-008 (Systemic): Comfort reading reports (rating)
9. FIN-009 (Systemic): Additional challenges (text)

### Each Question Has:
- Full DISC scoring (D, I, S, C personality types)
- Full Phase scoring (Stabilize, Organize, Build, Grow, Systemic)
- Realistic weights matching business requirements

## Console Output

Open browser DevTools Console to see:

```
[API Client] Using MOCK API
```

When you answer questions, you'll see auto-save activity:
```
Auto-save triggered...
Response saved successfully
```

## Switch to Real API

When backend is ready:

1. Edit `.env`:
   ```bash
   VITE_USE_MOCK_API=false
   VITE_API_BASE_URL=https://your-backend-url.com/api/v1
   ```

2. Restart dev server:
   ```bash
   npm run dev
   ```

That's it! No code changes needed.

## Testing

Run the test suite:

```bash
# All tests
npm test

# With coverage report
npm run test:coverage

# Watch mode (interactive)
npm run test:watch

# UI mode (visual test runner)
npm run test:ui
```

## Architecture

```
Frontend App
├── apiClient (facade)
│   ├── Mock Mode → mockApi.ts (710 lines)
│   └── Real Mode → api.ts (connects to backend)
│
├── Components
│   ├── SingleChoiceQuestion
│   ├── MultipleChoiceQuestion
│   ├── RatingQuestion
│   └── TextQuestion
│
├── Pages
│   └── Questionnaire (multi-step form)
│
├── Store (Zustand)
│   └── assessmentStore (responses, progress, state)
│
└── Hooks
    └── useAutoSave (30s debounce)
```

## What's Mocked

- Full questionnaire data (9 questions)
- Assessment CRUD operations
- Response submission and updates
- Progress calculation
- Report generation endpoints
- Network latency (200-1500ms realistic delays)

## What's Real

- All UI components (production code)
- State management (Zustand store)
- Auto-save logic (30s debounce)
- Form validation
- Navigation logic
- Progress calculation
- Test suite

## API Contract Compliance

Mock API matches `API-CONTRACT.md` v1.0 exactly:

- ✅ All endpoint paths match
- ✅ All request/response structures match
- ✅ All status codes match
- ✅ All error formats match
- ✅ Realistic latency simulated
- ✅ Data types and validation rules match

## Troubleshooting

### Issue: "VITE_USE_MOCK_API is not defined"
**Solution:** Make sure `.env` file exists with `VITE_USE_MOCK_API=true`

### Issue: "Assessment not found"
**Solution:** Use one of the seeded assessment IDs:
- `a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d`
- `b2c3d4e5-f6a7-5b6c-9d0e-1f2a3b4c5d6e`

### Issue: Tests not running
**Solution:** Run `npm install` to ensure vitest is installed

### Issue: Auto-save not working
**Solution:** Check console for errors. Auto-save only triggers when:
- Dirty state is true (you changed an answer)
- 30 seconds have elapsed
- Assessment ID is valid

## File Locations

- Mock API: `src/services/mockApi.ts`
- API Facade: `src/services/apiClient.ts`
- Questionnaire Page: `src/pages/Questionnaire.tsx`
- Question Components: `src/components/Questions/*.tsx`
- Tests: `src/components/Questions/__tests__/*.test.tsx`
- Store: `src/store/assessmentStore.ts`
- Auto-save Hook: `src/hooks/useAutoSave.ts`

## Next Steps

1. Play with the UI - answer questions, navigate, use features
2. Check console logs - see auto-save in action
3. Run tests - see comprehensive coverage
4. Read `QUESTIONNAIRE-UI-README.md` - full implementation details
5. When backend is ready - toggle to real API with one line change

## Need Help?

- Check `QUESTIONNAIRE-UI-README.md` for comprehensive documentation
- Check `API-CONTRACT.md` for endpoint specifications
- Check component tests for usage examples
- Check `TEAM-COORDINATION.md` for team status

---

**Happy Testing!** 🎉

The questionnaire UI is production-ready and waiting for backend integration.
