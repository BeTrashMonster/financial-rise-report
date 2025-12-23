import React from 'react';
import { Box, Typography, Link, Paper } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';

export interface PDFViewerProps {
  pdfUrl: string;
  title?: string;
  width?: string;
  height?: string;
  className?: string;
}

export const PDFViewer: React.FC<PDFViewerProps> = ({
  pdfUrl,
  title = 'PDF Viewer',
  width = '100%',
  height = '600px',
  className,
}) => {
  if (!pdfUrl) {
    return (
      <Paper sx={{ p: 4, textAlign: 'center' }} className={className}>
        <Typography color="text.secondary">No PDF available</Typography>
      </Paper>
    );
  }

  return (
    <Box className={className}>
      <Box sx={{ mb: 2, display: 'flex', justifyContent: 'flex-end' }}>
        <Link
          href={pdfUrl}
          download
          target="_blank"
          rel="noopener noreferrer"
          sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}
        >
          <DownloadIcon fontSize="small" />
          Download PDF
        </Link>
      </Box>
      <Paper elevation={2}>
        <iframe
          src={pdfUrl}
          title={title}
          aria-label={title}
          style={{
            width,
            height,
            border: 'none',
            display: 'block',
          }}
        />
      </Paper>
    </Box>
  );
};
