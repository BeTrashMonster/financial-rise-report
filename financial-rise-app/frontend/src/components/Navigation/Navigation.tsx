/**
 * Navigation Component
 * Work Stream 7: Navigation Bar & Menu
 *
 * Features:
 * - App bar with branding and navigation links
 * - User menu with logout
 * - Mobile-responsive hamburger menu
 * - Active route highlighting
 * - Accessible navigation (WCAG 2.1 AA)
 */

import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  AppBar,
  Box,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Container,
  useMediaQuery,
  useTheme,
  Divider,
} from '@mui/material';
import {
  Menu as MenuIcon,
  AccountCircle as AccountCircleIcon,
  Dashboard as DashboardIcon,
  Assessment as AssessmentIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { logout } from '@store/slices/authSlice';

interface NavLink {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const navLinks: NavLink[] = [
  { label: 'Dashboard', path: '/dashboard', icon: <DashboardIcon /> },
  { label: 'Assessments', path: '/assessments', icon: <AssessmentIcon /> },
];

export const Navigation: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const { user, isAuthenticated } = useAppSelector((state) => state.auth);

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userMenuAnchor, setUserMenuAnchor] = useState<null | HTMLElement>(null);

  const handleLogout = () => {
    dispatch(logout());
    setUserMenuAnchor(null);
    navigate('/login');
  };

  const handleNavClick = (path: string) => {
    navigate(path);
    setMobileMenuOpen(false);
  };

  const isActivePath = (path: string) => {
    return location.pathname === path || location.pathname.startsWith(`${path}/`);
  };

  // Don't show navigation on login page or if not authenticated
  if (!isAuthenticated || location.pathname === '/login') {
    return null;
  }

  return (
    <AppBar position="sticky" color="primary" elevation={2}>
      <Container maxWidth="xl">
        <Toolbar disableGutters>
          {/* Logo/Brand */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              cursor: 'pointer',
              mr: { xs: 2, md: 4 },
            }}
            onClick={() => navigate('/dashboard')}
          >
            <Typography
              variant="h6"
              component="h1"
              sx={{
                fontWeight: 700,
                color: 'white',
                textDecoration: 'none',
                fontSize: { xs: '1rem', md: '1.25rem' },
              }}
            >
              Financial RISE
            </Typography>
          </Box>

          {/* Desktop Navigation Links */}
          {!isMobile && (
            <Box sx={{ flexGrow: 1, display: 'flex', gap: 1 }}>
              {navLinks.map((link) => (
                <Button
                  key={link.path}
                  onClick={() => handleNavClick(link.path)}
                  startIcon={link.icon}
                  sx={{
                    color: 'white',
                    backgroundColor: isActivePath(link.path)
                      ? 'rgba(255, 255, 255, 0.15)'
                      : 'transparent',
                    '&:hover': {
                      backgroundColor: 'rgba(255, 255, 255, 0.2)',
                    },
                    borderRadius: 1,
                    px: 2,
                  }}
                  aria-current={isActivePath(link.path) ? 'page' : undefined}
                >
                  {link.label}
                </Button>
              ))}
            </Box>
          )}

          {/* Mobile Menu Button */}
          {isMobile && (
            <Box sx={{ flexGrow: 1, display: 'flex', justifyContent: 'flex-end' }}>
              <IconButton
                size="large"
                edge="start"
                color="inherit"
                aria-label="Open navigation menu"
                onClick={() => setMobileMenuOpen(true)}
              >
                <MenuIcon />
              </IconButton>
            </Box>
          )}

          {/* Desktop User Menu */}
          {!isMobile && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" sx={{ color: 'white', mr: 1 }}>
                {user?.email || 'User'}
              </Typography>
              <IconButton
                size="large"
                edge="end"
                aria-label="User account menu"
                aria-controls="user-menu"
                aria-haspopup="true"
                onClick={(e) => setUserMenuAnchor(e.currentTarget)}
                color="inherit"
              >
                <AccountCircleIcon />
              </IconButton>
              <Menu
                id="user-menu"
                anchorEl={userMenuAnchor}
                open={Boolean(userMenuAnchor)}
                onClose={() => setUserMenuAnchor(null)}
                anchorOrigin={{
                  vertical: 'bottom',
                  horizontal: 'right',
                }}
                transformOrigin={{
                  vertical: 'top',
                  horizontal: 'right',
                }}
              >
                <MenuItem
                  onClick={() => {
                    navigate('/profile');
                    setUserMenuAnchor(null);
                  }}
                >
                  Profile
                </MenuItem>
                <MenuItem onClick={handleLogout}>Logout</MenuItem>
              </Menu>
            </Box>
          )}
        </Toolbar>
      </Container>

      {/* Mobile Drawer */}
      <Drawer
        anchor="right"
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
        sx={{
          '& .MuiDrawer-paper': {
            width: 280,
          },
        }}
      >
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6" fontWeight={600}>
            Menu
          </Typography>
          <IconButton
            onClick={() => setMobileMenuOpen(false)}
            aria-label="Close navigation menu"
          >
            <CloseIcon />
          </IconButton>
        </Box>
        <Divider />

        {/* User Info */}
        <Box sx={{ p: 2, bgcolor: 'grey.100' }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Signed in as
          </Typography>
          <Typography variant="body1" fontWeight={600}>
            {user?.email || 'User'}
          </Typography>
        </Box>
        <Divider />

        {/* Navigation Links */}
        <List>
          {navLinks.map((link) => (
            <ListItem key={link.path} disablePadding>
              <ListItemButton
                onClick={() => handleNavClick(link.path)}
                selected={isActivePath(link.path)}
                sx={{
                  py: 1.5,
                  '&.Mui-selected': {
                    bgcolor: 'primary.light',
                    color: 'primary.contrastText',
                    '&:hover': {
                      bgcolor: 'primary.main',
                    },
                  },
                }}
              >
                <Box sx={{ mr: 2, display: 'flex', alignItems: 'center' }}>
                  {link.icon}
                </Box>
                <ListItemText
                  primary={link.label}
                  primaryTypographyProps={{ fontWeight: 500 }}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
        <Divider />

        {/* Profile & Logout */}
        <List>
          <ListItem disablePadding>
            <ListItemButton
              onClick={() => {
                navigate('/profile');
                setMobileMenuOpen(false);
              }}
              sx={{ py: 1.5 }}
            >
              <ListItemText primary="Profile" />
            </ListItemButton>
          </ListItem>
          <ListItem disablePadding>
            <ListItemButton onClick={handleLogout} sx={{ py: 1.5 }}>
              <ListItemText primary="Logout" />
            </ListItemButton>
          </ListItem>
        </List>
      </Drawer>
    </AppBar>
  );
};

export default Navigation;
