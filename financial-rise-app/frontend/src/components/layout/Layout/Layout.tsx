import React from 'react';
import { Box } from '@mui/material';
import { Header } from '../Header/Header';
import { Footer } from '../Footer/Footer';

export interface LayoutProps {
  children: React.ReactNode;
  showHeader?: boolean;
  showFooter?: boolean;
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | false;
}

/**
 * Main Layout Component
 * Wraps pages with consistent header and footer
 */
export const Layout: React.FC<LayoutProps> = ({
  children,
  showHeader = true,
  showFooter = true,
  maxWidth = 'lg',
}) => {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        minHeight: '100vh',
      }}
    >
      {showHeader && <Header />}

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          width: '100%',
          maxWidth: maxWidth ? `${maxWidth}` : undefined,
          margin: maxWidth ? '0 auto' : undefined,
          paddingX: { xs: 2, sm: 3, md: 4 },
          paddingY: { xs: 3, sm: 4 },
        }}
        role="main"
      >
        {children}
      </Box>

      {showFooter && <Footer />}
    </Box>
  );
};

export default Layout;
