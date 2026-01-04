import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAppSelector } from '@store/hooks';

// Lazy load pages
const Login = React.lazy(() => import('@pages/Login/Login'));
const Dashboard = React.lazy(() => import('@pages/Dashboard/Dashboard'));
const AssessmentList = React.lazy(() => import('@pages/Assessments/AssessmentList'));
const CreateAssessment = React.lazy(() => import('@pages/Assessments/CreateAssessment'));
const Questionnaire = React.lazy(() => import('@pages/Questionnaire/Questionnaire'));
const Results = React.lazy(() => import('@pages/Results/Results'));
const UserProfile = React.lazy(() => import('@pages/UserProfile/UserProfile'));
const Privacy = React.lazy(() => import('@pages/Privacy/Privacy'));
const DoNotSell = React.lazy(() => import('@pages/DoNotSell/DoNotSell'));

/**
 * Protected Route Component
 * Redirects to login if not authenticated
 */
interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated } = useAppSelector((state) => state.auth);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

/**
 * Application Routes
 */
export const AppRoutes: React.FC = () => {
  return (
    <React.Suspense fallback={<div>Loading...</div>}>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/do-not-sell" element={<DoNotSell />} />

        {/* Protected Routes */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/home"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/assessments"
          element={
            <ProtectedRoute>
              <AssessmentList />
            </ProtectedRoute>
          }
        />
        <Route
          path="/assessments/new"
          element={
            <ProtectedRoute>
              <CreateAssessment />
            </ProtectedRoute>
          }
        />
        <Route
          path="/assessments/:assessmentId/questionnaire"
          element={
            <ProtectedRoute>
              <Questionnaire />
            </ProtectedRoute>
          }
        />
        <Route
          path="/assessments/:assessmentId/results"
          element={
            <ProtectedRoute>
              <Results />
            </ProtectedRoute>
          }
        />
        <Route
          path="/profile"
          element={
            <ProtectedRoute>
              <UserProfile />
            </ProtectedRoute>
          }
        />

        {/* Default Route */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        {/* 404 Not Found */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </React.Suspense>
  );
};
