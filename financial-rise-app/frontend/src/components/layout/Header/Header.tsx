import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Box,
  Avatar,
  Menu,
  MenuItem,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch, useAppSelector } from '@store/hooks';
import { logout } from '@store/slices/authSlice';

export interface HeaderProps {
  onMenuClick?: () => void;
}

/**
 * Application Header Component
 * Displays navigation, branding, and user menu
 */
export const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const navigate = useNavigate();
  const dispatch = useAppDispatch();

  const { isAuthenticated, user } = useAppSelector((state) => state.auth);
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    dispatch(logout());
    handleMenuClose();
    navigate('/login');
  };

  const handleProfile = () => {
    handleMenuClose();
    navigate('/profile');
  };

  return (
    <AppBar position="sticky" color="primary">
      <Toolbar>
        {isMobile && isAuthenticated && (
          <IconButton
            color="inherit"
            aria-label="Open navigation menu"
            edge="start"
            onClick={onMenuClick}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
        )}

        <Typography
          variant="h6"
          component="h1"
          sx={{
            flexGrow: 0,
            fontWeight: 700,
            cursor: 'pointer',
            letterSpacing: 0.5,
          }}
          onClick={() => navigate(isAuthenticated ? '/dashboard' : '/')}
        >
          Financial RISE
        </Typography>

        <Box sx={{ flexGrow: 1 }} />

        {isAuthenticated ? (
          <>
            {!isMobile && (
              <Box sx={{ display: 'flex', gap: 2, mr: 2 }}>
                <Button
                  color="inherit"
                  onClick={() => navigate('/dashboard')}
                  aria-label="Go to dashboard"
                >
                  Dashboard
                </Button>
                <Button
                  color="inherit"
                  onClick={() => navigate('/assessments')}
                  aria-label="Go to assessments"
                >
                  Assessments
                </Button>
              </Box>
            )}

            <IconButton
              onClick={handleMenuOpen}
              aria-label="User menu"
              aria-controls="user-menu"
              aria-haspopup="true"
              color="inherit"
            >
              {user?.avatar ? (
                <Avatar
                  src={user.avatar}
                  alt={user.name}
                  sx={{ width: 32, height: 32 }}
                />
              ) : (
                <AccountCircleIcon />
              )}
            </IconButton>

            <Menu
              id="user-menu"
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'right',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'right',
              }}
            >
              <MenuItem onClick={handleProfile}>Profile</MenuItem>
              <MenuItem onClick={handleLogout}>Logout</MenuItem>
            </Menu>
          </>
        ) : (
          <Button
            color="inherit"
            onClick={() => navigate('/login')}
            aria-label="Login"
          >
            Login
          </Button>
        )}
      </Toolbar>
    </AppBar>
  );
};

export default Header;
