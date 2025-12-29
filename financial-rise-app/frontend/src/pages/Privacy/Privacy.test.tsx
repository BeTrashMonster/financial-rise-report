import { render, screen } from '../../test/test-utils';
import { describe, it, expect } from 'vitest';
import Privacy from './Privacy';

describe('Privacy Component', () => {
  it('should render the Privacy Policy page', () => {
    render(<Privacy />);

    // Check for main heading using role
    expect(screen.getByRole('heading', { name: /Privacy Policy/i, level: 1 })).toBeInTheDocument();
  });

  it('should display all major sections', () => {
    render(<Privacy />);

    expect(screen.getByRole('heading', { name: /2\. Information We Collect/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /3\. How We Use Your Information/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /4\. Information Sharing and Disclosure/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /5\. Data Security/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /7\. Your Privacy Rights/i })).toBeInTheDocument();
  });

  it('should include GDPR rights section', () => {
    render(<Privacy />);

    expect(screen.getByText(/GDPR Rights \(European Users\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Right of Access/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Rectification/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Erasure/i)).toBeInTheDocument();
  });

  it('should include CCPA rights section', () => {
    render(<Privacy />);

    expect(screen.getByText(/CCPA Rights \(California Residents\)/i)).toBeInTheDocument();
  });

  it('should state that data is NOT sold', () => {
    render(<Privacy />);

    expect(screen.getByText(/We Do NOT Sell Your Personal Information/i)).toBeInTheDocument();
  });

  it('should have link to Do Not Sell page', () => {
    render(<Privacy />);

    const doNotSellLink = screen.getByRole('link', { name: /Do Not Sell My Personal Information/i });
    expect(doNotSellLink).toHaveAttribute('href', '/do-not-sell');
  });

  it('should display contact information', () => {
    render(<Privacy />);

    expect(screen.getByText(/privacy@financialrise.com/i)).toBeInTheDocument();
  });

  it('should display effective date', () => {
    render(<Privacy />);

    expect(screen.getByText(/Effective Date:/i)).toBeInTheDocument();
    expect(screen.getByText(/Last Updated:/i)).toBeInTheDocument();
  });
});
