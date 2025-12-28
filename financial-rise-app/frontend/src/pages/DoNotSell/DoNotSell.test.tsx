import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import DoNotSell from './DoNotSell';

describe('DoNotSell Component', () => {
  it('should render the CCPA notice page', () => {
    render(
      <BrowserRouter>
        <DoNotSell />
      </BrowserRouter>
    );

    // Check for main heading
    expect(screen.getByText(/Do Not Sell My Personal Information/i)).toBeInTheDocument();
  });

  it('should display notice that data is NOT sold', () => {
    render(
      <BrowserRouter>
        <DoNotSell />
      </BrowserRouter>
    );

    expect(screen.getByText(/We Do NOT Sell Your Personal Information/i)).toBeInTheDocument();
  });

  it('should list CCPA rights', () => {
    render(
      <BrowserRouter>
        <DoNotSell />
      </BrowserRouter>
    );

    expect(screen.getByText(/Right to Know/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Delete/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Opt-Out/i)).toBeInTheDocument();
    expect(screen.getByText(/Right to Non-Discrimination/i)).toBeInTheDocument();
  });

  it('should have link to Privacy Policy', () => {
    render(
      <BrowserRouter>
        <DoNotSell />
      </BrowserRouter>
    );

    const privacyLink = screen.getByRole('link', { name: /Privacy Policy/i });
    expect(privacyLink).toHaveAttribute('href', '/privacy');
  });

  it('should display contact information', () => {
    render(
      <BrowserRouter>
        <DoNotSell />
      </BrowserRouter>
    );

    expect(screen.getByText(/privacy@financialrise.com/i)).toBeInTheDocument();
  });
});
