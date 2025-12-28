import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import Privacy from './Privacy';

describe('Privacy Component', () => {
  it('should render the Privacy Policy page', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    // Check for main heading
    expect(screen.getByText(/Privacy Policy/i)).toBeInTheDocument();
  });

  it('should display all major sections', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/Information We Collect/i)).toBeInTheDocument();
    expect(screen.getByText(/How We Use Your Information/i)).toBeInTheDocument();
    expect(screen.getByText(/Information Sharing and Disclosure/i)).toBeInTheDocument();
    expect(screen.getByText(/Data Security/i)).toBeInTheDocument();
    expect(screen.getByText(/Your Privacy Rights/i)).toBeInTheDocument();
  });

  it('should include GDPR rights section', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/GDPR Rights \(European Users\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Right of Access/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Rectification/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Erasure/i)).toBeInTheDocument();
  });

  it('should include CCPA rights section', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/CCPA Rights \(California Residents\)/i)).toBeInTheDocument();
  });

  it('should state that data is NOT sold', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/We Do NOT Sell Your Personal Information/i)).toBeInTheDocument();
  });

  it('should have link to Do Not Sell page', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    const doNotSellLink = screen.getByRole('link', { name: /Do Not Sell My Personal Information/i });
    expect(doNotSellLink).toHaveAttribute('href', '/do-not-sell');
  });

  it('should display contact information', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/privacy@financialrise.com/i)).toBeInTheDocument();
  });

  it('should display effective date', () => {
    render(
      <BrowserRouter>
        <Privacy />
      </BrowserRouter>
    );

    expect(screen.getByText(/December 28, 2025/i)).toBeInTheDocument();
  });
});
