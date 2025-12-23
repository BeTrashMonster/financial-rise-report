import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PDFViewer } from '../PDFViewer';

describe('PDFViewer', () => {
  const mockPdfUrl = 'https://example.com/report.pdf';

  it('renders an iframe with the PDF URL', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} />);

    const iframe = screen.getByTitle(/pdf viewer/i);
    expect(iframe).toBeInTheDocument();
    expect(iframe).toHaveAttribute('src', mockPdfUrl);
  });

  it('renders with custom title', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} title="Financial Report" />);

    const iframe = screen.getByTitle(/financial report/i);
    expect(iframe).toBeInTheDocument();
  });

  it('has full width and height by default', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} />);

    const iframe = screen.getByTitle(/pdf viewer/i);
    expect(iframe).toHaveStyle({ width: '100%', height: '600px' });
  });

  it('accepts custom width and height', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} width="800px" height="400px" />);

    const iframe = screen.getByTitle(/pdf viewer/i);
    expect(iframe).toHaveStyle({ width: '800px', height: '400px' });
  });

  it('shows download link', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} />);

    const downloadLink = screen.getByText(/download pdf/i).closest('a');
    expect(downloadLink).toHaveAttribute('href', mockPdfUrl);
    expect(downloadLink).toHaveAttribute('download');
  });

  it('has proper accessibility attributes', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} />);

    const iframe = screen.getByTitle(/pdf viewer/i);
    expect(iframe).toHaveAttribute('title');
    expect(iframe).toHaveAttribute('aria-label');
  });

  it('renders loading fallback when PDF is not available', () => {
    render(<PDFViewer pdfUrl="" />);

    expect(screen.getByText(/no pdf available/i)).toBeInTheDocument();
  });

  it('allows custom CSS class names', () => {
    render(<PDFViewer pdfUrl={mockPdfUrl} className="custom-pdf-viewer" />);

    const container = screen.getByTitle(/pdf viewer/i).parentElement;
    expect(container).toHaveClass('custom-pdf-viewer');
  });
});
