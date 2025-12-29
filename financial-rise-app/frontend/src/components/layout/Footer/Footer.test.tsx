import { render, screen } from '../../../test/test-utils';
import { describe, it, expect } from 'vitest';
import { Footer } from './Footer';

describe('Footer Component', () => {
  it('should render the footer', () => {
    render(<Footer />);

    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
  });

  it('should display company name and tagline', () => {
    render(<Footer />);

    expect(screen.getByText(/Financial RISE Report/i)).toBeInTheDocument();
    expect(screen.getByText(/Readiness Insights for Sustainable Entrepreneurship/i)).toBeInTheDocument();
  });

  it('should have Privacy Policy link', () => {
    render(<Footer />);

    const privacyLink = screen.getByRole('link', { name: /Privacy Policy/i });
    expect(privacyLink).toHaveAttribute('href', '/privacy');
  });

  it('should have Terms of Service link', () => {
    render(<Footer />);

    const termsLink = screen.getByRole('link', { name: /Terms of Service/i });
    expect(termsLink).toHaveAttribute('href', '/terms');
  });

  it('should have Contact link', () => {
    render(<Footer />);

    const contactLink = screen.getByRole('link', { name: /Contact/i });
    expect(contactLink).toHaveAttribute('href', '/contact');
  });

  it('should have prominent CCPA "Do Not Sell" link with icon', () => {
    render(<Footer />);

    // Check for CCPA link
    const ccpaLink = screen.getByRole('link', { name: /Do Not Sell My Personal Information/i });
    expect(ccpaLink).toBeInTheDocument();
    expect(ccpaLink).toHaveAttribute('href', '/do-not-sell');
  });

  it('should display copyright notice with current year', () => {
    render(<Footer />);

    const currentYear = new Date().getFullYear();
    expect(screen.getByText(new RegExp(`© ${currentYear} Financial RISE`, 'i'))).toBeInTheDocument();
  });

  it('should have proper ARIA role for accessibility', () => {
    render(<Footer />);

    const footer = screen.getByRole('contentinfo');
    expect(footer).toBeInTheDocument();
  });
});
