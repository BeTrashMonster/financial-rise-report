# Financial RISE Report - Frontend

React 18 frontend application for the Financial RISE Report (Readiness Insights for Sustainable Entrepreneurship) assessment tool.

## Technology Stack

- **React 18.2+** - UI framework
- **TypeScript 5.3+** - Type safety
- **Vite 5.1+** - Build tool and dev server
- **Material-UI 5.15+** - Component library
- **Redux Toolkit 2.1+** - State management
- **React Router 6.22+** - Client-side routing
- **React Hook Form 7.50+** - Form management
- **Axios 1.6+** - HTTP client
- **Vitest** - Unit testing

## Brand Guidelines

- **Primary Color:** Purple #4B006E
- **Secondary Color:** Metallic Gold #D4AF37
- **Typography:** Calibri (14px minimum)
- **Design:** Black on white, accessible (WCAG 2.1 Level AA)

## Getting Started

### Prerequisites

- Node.js 18+ and npm 9+
- Backend API running on `http://localhost:4000` (or configure `VITE_API_URL`)

### Installation

```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env

# Start development server
npm run dev
```

The application will be available at `http://localhost:3000`.

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
VITE_API_URL=http://localhost:4000
VITE_API_TIMEOUT=30000
VITE_APP_NAME=Financial RISE Report
```

## Available Scripts

```bash
# Development
npm run dev              # Start dev server (port 3000)
npm run build            # Build for production
npm run preview          # Preview production build

# Code Quality
npm run lint             # Run ESLint
npm run type-check       # Run TypeScript type checking

# Testing
npm run test             # Run tests in watch mode
npm run test:ui          # Run tests with UI
npm run test:coverage    # Generate coverage report
```

## Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── common/          # Generic components (Button, Input, Card, Modal)
│   │   └── layout/          # Layout components (Header, Footer, Layout)
│   ├── pages/               # Page components
│   │   ├── Login/           # Login page
│   │   ├── Dashboard/       # Dashboard page
│   │   └── NotFound/        # 404 page
│   ├── services/            # API services
│   │   ├── api.ts           # Axios instance with interceptors
│   │   ├── authService.ts   # Authentication API
│   │   └── assessmentService.ts  # Assessment API
│   ├── store/               # Redux state management
│   │   ├── store.ts         # Store configuration
│   │   ├── hooks.ts         # Typed hooks
│   │   └── slices/          # Redux slices
│   │       ├── authSlice.ts
│   │       └── assessmentSlice.ts
│   ├── theme/               # Material-UI theme
│   │   ├── theme.ts         # Theme configuration
│   │   ├── colors.ts        # Color palette
│   │   └── typography.ts    # Typography settings
│   ├── routes/              # Route configuration
│   │   └── index.tsx        # Route definitions
│   ├── test/                # Test utilities
│   │   └── setup.ts         # Vitest setup
│   ├── App.tsx              # Main app component
│   └── main.tsx             # Entry point
├── public/                  # Static assets
├── index.html               # HTML template
├── vite.config.ts           # Vite configuration
├── tsconfig.json            # TypeScript configuration
├── package.json             # Dependencies
└── README.md                # This file
```

## Component Library

### Common Components

All components follow accessibility best practices and brand guidelines:

- **Button** - Custom button with loading state
- **Input** - Text input with validation and password toggle
- **Card** - Content card with header, actions, and divider options
- **Modal** - Accessible dialog with customizable title and actions

### Layout Components

- **Header** - App header with navigation and user menu
- **Footer** - App footer with links and copyright
- **Layout** - Main layout wrapper with header and footer

### Usage Example

```tsx
import Button from '@components/common/Button/Button';
import Input from '@components/common/Input/Input';
import Card from '@components/common/Card/Card';

<Card title="Form" divider>
  <Input
    label="Email"
    type="email"
    fullWidth
    error={!!errors.email}
    helperText={errors.email?.message}
  />
  <Button variant="contained" loading={isLoading}>
    Submit
  </Button>
</Card>
```

## State Management

### Redux Store

The application uses Redux Toolkit for state management:

- **authSlice** - User authentication state
- **assessmentSlice** - Assessment data and questions

### Usage Example

```tsx
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { login } from '@store/slices/authSlice';

const { user, isAuthenticated } = useAppSelector((state) => state.auth);
const dispatch = useAppDispatch();

const handleLogin = async (credentials) => {
  await dispatch(login(credentials));
};
```

## API Integration

### Services

All API calls are centralized in service files:

- **authService** - Login, register, logout, password reset
- **assessmentService** - CRUD operations for assessments

### Usage Example

```tsx
import { authService } from '@services/authService';

const response = await authService.login({ email, password });
```

## Routing

Protected routes require authentication. Public routes redirect authenticated users to dashboard.

```tsx
<Routes>
  <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
  <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
  <Route path="*" element={<NotFound />} />
</Routes>
```

## Accessibility

- All interactive elements have proper ARIA labels
- Keyboard navigation fully supported
- Color contrast meets WCAG 2.1 Level AA standards
- Screen reader friendly
- Minimum 14px font size (per requirements)

## Docker Deployment

Build and run with Docker:

```bash
# Build image
docker build -t financial-rise-frontend .

# Run container
docker run -p 80:80 financial-rise-frontend
```

The Dockerfile uses multi-stage builds with nginx for optimal production deployment.

## Code Quality

### TypeScript

Strict mode enabled for type safety. All components and functions are properly typed.

### Linting

ESLint configured with React and TypeScript rules. Run `npm run lint` before commits.

### Testing

Unit tests use Vitest and React Testing Library. Aim for 80%+ code coverage per requirements.

```bash
npm run test:coverage
```

## Performance

- Code splitting for vendor, MUI, and Redux bundles
- Lazy loading for route components
- Optimized production builds with Vite
- Nginx gzip compression and caching
- Target: <3 second page loads (REQ-PERF-001)

## Browser Support

- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)

## Related Documentation

- [Requirements Specification](../../plans/requirements.md)
- [Implementation Roadmap](../../plans/roadmap.md)
- [Backend API Documentation](../backend/README.md)

## Contributing

Follow the project workflow defined in `/plans/roadmap.md`. Update task statuses when completing work streams.

## License

Copyright 2025 Financial RISE. All rights reserved.
