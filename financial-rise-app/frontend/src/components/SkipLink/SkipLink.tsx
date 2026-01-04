/**
 * Skip to Main Content Link
 * Work Stream 12: Accessibility Compliance (REQ-ACCESS-006)
 *
 * Provides keyboard users with a quick way to skip repetitive navigation
 * and jump directly to the main content area.
 *
 * This link is visually hidden but becomes visible when focused via keyboard.
 */

import React from 'react';
import { Box } from '@mui/material';

interface SkipLinkProps {
  /** The ID of the main content element to skip to */
  targetId?: string;
}

export const SkipLink: React.FC<SkipLinkProps> = ({ targetId = 'main-content' }) => {
  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const target = document.getElementById(targetId);
    if (target) {
      target.focus();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <Box
      component="a"
      href={`#${targetId}`}
      onClick={handleClick}
      sx={{
        position: 'absolute',
        left: '-9999px',
        zIndex: 9999,
        padding: '12px 24px',
        backgroundColor: 'primary.main',
        color: 'primary.contrastText',
        textDecoration: 'none',
        fontSize: '1rem',
        fontWeight: 600,
        borderRadius: '0 0 8px 8px',
        boxShadow: '0px 4px 8px rgba(0, 0, 0, 0.2)',
        '&:focus': {
          left: '16px',
          top: '16px',
          outline: '3px solid',
          outlineColor: 'secondary.main',
          outlineOffset: '2px',
        },
      }}
    >
      Skip to main content
    </Box>
  );
};

export default SkipLink;
