import { render, screen } from '../../test/test-utils';
import { describe, it, expect } from 'vitest';
import DoNotSell from './DoNotSell';

describe('DoNotSell Component', () => {
  it('should render the CCPA notice page', () => {
    render(<DoNotSell />);

    // Check for main heading
    expect(screen.getByText(/Do Not Sell My Personal Information/i)).toBeInTheDocument();
  });

  it('should display notice that data is NOT sold', () => {
    render(<DoNotSell />);

    expect(screen.getByText(/We Do NOT Sell Your Personal Information/i)).toBeInTheDocument();
  });

  it('should list CCPA rights', () => {
    render(<DoNotSell />);

    expect(screen.getByText(/Right to Know/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Delete/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Opt-Out/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Non-Discrimination/i)).toBeInTheDocument();
  });

  it('should have link to Privacy Policy', () => {
    render(<DoNotSell />);

    const privacyLink = screen.getByRole('link', { name: /Privacy Policy/i });
    expect(privacyLink).toHaveAttribute('href', '/privacy');
  });

  it('should display contact information', () => {
    render(<DoNotSell />);

    expect(screen.getByText(/privacy@financialrise.com/i)).toBeInTheDocument();
  });
});
