import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { AutoSaveIndicator } from '../AutoSaveIndicator';

describe('AutoSaveIndicator', () => {
  it('should show saving state', () => {
    render(<AutoSaveIndicator isSaving={true} isDirty={false} lastSavedAt={null} />);
    expect(screen.getByText('Saving...')).toBeInTheDocument();
  });

  it('should show unsaved changes state', () => {
    render(<AutoSaveIndicator isSaving={false} isDirty={true} lastSavedAt={null} />);
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();
  });

  it('should show saved state with timestamp', () => {
    const savedAt = new Date();
    render(<AutoSaveIndicator isSaving={false} isDirty={false} lastSavedAt={savedAt} />);
    expect(screen.getByText(/Saved.*ago/)).toBeInTheDocument();
  });

  it('should not render when nothing to show', () => {
    const { container } = render(<AutoSaveIndicator isSaving={false} isDirty={false} lastSavedAt={null} />);
    expect(container.firstChild).toBeNull();
  });

  it('should have accessible labels', () => {
    render(<AutoSaveIndicator isSaving={true} isDirty={false} lastSavedAt={null} />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-label', 'Saving changes');
  });
});
