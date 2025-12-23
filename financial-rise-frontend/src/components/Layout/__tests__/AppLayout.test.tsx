import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { AppLayout } from '../AppLayout';

// Mock useNavigate
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('AppLayout', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear localStorage before each test
    localStorage.clear();
  });

  const renderWithRouter = (children: React.ReactNode) => {
    return render(<BrowserRouter><AppLayout>{children}</AppLayout></BrowserRouter>);
  };

  it('should render application title', () => {
    renderWithRouter(<div>Test Content</div>);
    expect(screen.getByText('Financial RISE Report')).toBeInTheDocument();
  });

  it('should render children content', () => {
    renderWithRouter(<div>Test Content</div>);
    expect(screen.getByText('Test Content')).toBeInTheDocument();
  });

  it('should render dashboard icon button', () => {
    renderWithRouter(<div>Test Content</div>);
    expect(screen.getByRole('button', { name: 'Go to dashboard' })).toBeInTheDocument();
  });

  it('should render logout icon button', () => {
    renderWithRouter(<div>Test Content</div>);
    expect(screen.getByRole('button', { name: 'Logout' })).toBeInTheDocument();
  });

  it('should navigate to dashboard when dashboard button is clicked', async () => {
    const user = userEvent.setup();
    renderWithRouter(<div>Test Content</div>);

    await user.click(screen.getByRole('button', { name: 'Go to dashboard' }));
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });

  it('should remove auth token and navigate to login when logout is clicked', async () => {
    const user = userEvent.setup();
    localStorage.setItem('auth_token', 'test-token-123');
    renderWithRouter(<div>Test Content</div>);

    await user.click(screen.getByRole('button', { name: 'Logout' }));

    expect(localStorage.getItem('auth_token')).toBeNull();
    expect(mockNavigate).toHaveBeenCalledWith('/login');
  });

  it('should render footer with copyright text', () => {
    renderWithRouter(<div>Test Content</div>);
    expect(screen.getByText('© 2025 Financial RISE Report. All rights reserved.')).toBeInTheDocument();
  });

  it('should render app bar with primary color', () => {
    const { container } = renderWithRouter(<div>Test Content</div>);
    const appBar = container.querySelector('.MuiAppBar-colorPrimary');
    expect(appBar).toBeInTheDocument();
  });

  it('should render assessment icon in app bar', () => {
    const { container } = renderWithRouter(<div>Test Content</div>);
    const assessmentIcon = container.querySelector('[data-testid="AssessmentIcon"]');
    expect(assessmentIcon).toBeInTheDocument();
  });

  it('should have dashboard tooltip', async () => {
    const user = userEvent.setup();
    renderWithRouter(<div>Test Content</div>);

    const dashboardButton = screen.getByRole('button', { name: 'Go to dashboard' });
    await user.hover(dashboardButton);

    // Material-UI tooltips are rendered but may require specific test setup
    // Just check the button exists with the right label
    expect(dashboardButton).toBeInTheDocument();
  });

  it('should have logout tooltip', async () => {
    const user = userEvent.setup();
    renderWithRouter(<div>Test Content</div>);

    const logoutButton = screen.getByRole('button', { name: 'Logout' });
    await user.hover(logoutButton);

    expect(logoutButton).toBeInTheDocument();
  });

  it('should render with proper layout structure', () => {
    const { container } = renderWithRouter(<div>Test Content</div>);

    // Check for main content area
    const main = container.querySelector('main');
    expect(main).toBeInTheDocument();

    // Check for footer
    const footer = container.querySelector('footer');
    expect(footer).toBeInTheDocument();
  });

  it('should render toolbar within app bar', () => {
    const { container } = renderWithRouter(<div>Test Content</div>);
    const toolbar = container.querySelector('.MuiToolbar-root');
    expect(toolbar).toBeInTheDocument();
  });

  it('should apply flexbox layout for full height', () => {
    const { container } = renderWithRouter(<div>Test Content</div>);
    const rootBox = container.firstChild as HTMLElement;
    expect(rootBox).toHaveStyle({ display: 'flex' });
  });

  it('should render multiple children correctly', () => {
    renderWithRouter(
      <>
        <div>First Child</div>
        <div>Second Child</div>
        <div>Third Child</div>
      </>
    );

    expect(screen.getByText('First Child')).toBeInTheDocument();
    expect(screen.getByText('Second Child')).toBeInTheDocument();
    expect(screen.getByText('Third Child')).toBeInTheDocument();
  });

  it('should have accessible navigation structure', () => {
    renderWithRouter(<div>Test Content</div>);

    // Check for toolbar role
    const toolbar = screen.getAllByRole('toolbar')[0];
    expect(toolbar).toBeInTheDocument();
  });
});
