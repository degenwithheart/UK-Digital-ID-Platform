import React, { useState, ReactNode } from 'react';
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Avatar,
  Menu,
  MenuItem,
  Badge,
  Divider,
  Tooltip,
  useMediaQuery,
  useTheme,
  Collapse,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard,
  AccountBox,
  Security,
  Assignment,
  Notifications,
  Settings,
  Logout,
  Help,
  Brightness4,
  Brightness7,
  ExpandLess,
  ExpandMore,
  Wallet,
  VerifiedUser,
  Group,
  History,
  Assessment,
} from '@mui/icons-material';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppSelector, useAppDispatch } from '@/store/hooks';
import { toggleSidebar } from '@/store/slices/uiSlice';
import { setThemeMode } from '@/store/slices/themeSlice';
import { logoutUser } from '@/store/slices/authSlice';
import NotificationPanel from './NotificationPanel';

interface LayoutProps {
  children: ReactNode;
}

interface NavigationItem {
  id: string;
  title: string;
  icon: ReactNode;
  href?: string;
  children?: NavigationItem[];
  badge?: number;
}

const DRAWER_WIDTH = 280;

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const router = useRouter();
  const dispatch = useAppDispatch();
  
  const { user } = useAppSelector((state) => state.auth);
  const { sidebarOpen } = useAppSelector((state) => state.ui);
  const { mode } = useAppSelector((state) => state.theme);
  const { unreadCount } = useAppSelector((state) => state.notifications);
  
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [expandedItems, setExpandedItems] = useState<string[]>([]);

  const navigationItems: NavigationItem[] = [
    {
      id: 'dashboard',
      title: 'Dashboard',
      icon: <Dashboard />,
      href: '/dashboard',
    },
    {
      id: 'wallet',
      title: 'Digital Wallet',
      icon: <Wallet />,
      children: [
        { id: 'credentials', title: 'My Credentials', icon: <VerifiedUser />, href: '/credentials' },
        { id: 'add-credential', title: 'Add Credential', icon: <Assignment />, href: '/credentials/add' },
      ],
    },
    {
      id: 'services',
      title: 'Government Services',
      icon: <Group />,
      href: '/services',
    },
    {
      id: 'activity',
      title: 'Activity History',
      icon: <History />,
      href: '/activity',
    },
    {
      id: 'reports',
      title: 'Reports & Analytics',
      icon: <Assessment />,
      href: '/reports',
    },
    {
      id: 'settings',
      title: 'Settings',
      icon: <Settings />,
      children: [
        { id: 'profile', title: 'Profile', icon: <AccountBox />, href: '/settings/profile' },
        { id: 'security', title: 'Security', icon: <Security />, href: '/settings/security' },
        { id: 'notifications', title: 'Notifications', icon: <Notifications />, href: '/settings/notifications' },
      ],
    },
  ];

  const handleDrawerToggle = () => {
    dispatch(toggleSidebar());
  };

  const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleProfileMenuClose = () => {
    setAnchorEl(null);
  };

  const handleThemeToggle = () => {
    const newMode = mode === 'light' ? 'dark' : 'light';
    dispatch(setThemeMode(newMode));
  };

  const handleLogout = () => {
    dispatch(logoutUser());
    router.push('/auth/login');
    handleProfileMenuClose();
  };

  const handleItemExpand = (itemId: string) => {
    setExpandedItems(prev => 
      prev.includes(itemId) 
        ? prev.filter(id => id !== itemId)
        : [...prev, itemId]
    );
  };

  const renderNavigationItem = (item: NavigationItem, depth = 0) => {
    const isActive = router.pathname === item.href;
    const isExpanded = expandedItems.includes(item.id);
    const hasChildren = item.children && item.children.length > 0;

    return (
      <React.Fragment key={item.id}>
        <ListItem disablePadding sx={{ pl: depth * 2 }}>
          <ListItemButton
            component={item.href ? Link : 'div'}
            href={item.href || undefined}
            selected={isActive}
            onClick={hasChildren ? () => handleItemExpand(item.id) : undefined}
            sx={{
              minHeight: 48,
              borderRadius: 1,
              mx: 1,
              '&.Mui-selected': {
                backgroundColor: 'primary.main',
                color: 'primary.contrastText',
                '&:hover': {
                  backgroundColor: 'primary.dark',
                },
                '& .MuiListItemIcon-root': {
                  color: 'primary.contrastText',
                },
              },
            }}
          >
            <ListItemIcon
              sx={{
                minWidth: 40,
                color: isActive ? 'inherit' : 'text.secondary',
              }}
            >
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.title}
              primaryTypographyProps={{
                variant: 'body2',
                fontWeight: isActive ? 600 : 400,
              }}
            />
            {item.badge && (
              <Badge badgeContent={item.badge} color="error" />
            )}
            {hasChildren && (isExpanded ? <ExpandLess /> : <ExpandMore />)}
          </ListItemButton>
        </ListItem>
        
        {hasChildren && (
          <Collapse in={isExpanded} timeout="auto" unmountOnExit>
            <List component="div" disablePadding>
              {item.children!.map(child => renderNavigationItem(child, depth + 1))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  const drawerContent = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Logo/Brand */}
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Typography variant="h6" noWrap component="div" fontWeight="bold">
          UK Digital ID
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Citizen Portal
        </Typography>
      </Box>

      {/* Navigation */}
      <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
        <List sx={{ pt: 2 }}>
          {navigationItems.map(item => renderNavigationItem(item))}
        </List>
      </Box>

      {/* User Info */}
      <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
        <Box display="flex" alignItems="center" mb={1}>
          <Avatar
            sx={{ width: 32, height: 32, mr: 1, bgcolor: 'primary.main' }}
          >
            {user?.firstName?.[0]}{user?.lastName?.[0]}
          </Avatar>
          <Box>
            <Typography variant="body2" fontWeight="medium">
              {user?.firstName} {user?.lastName}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {user?.verificationLevel?.replace('_', ' ').toUpperCase()}
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          width: { md: `calc(100% - ${sidebarOpen ? DRAWER_WIDTH : 0}px)` },
          ml: { md: sidebarOpen ? `${DRAWER_WIDTH}px` : 0 },
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="toggle drawer"
            onClick={handleDrawerToggle}
            edge="start"
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>

          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            {router.pathname === '/dashboard' && 'Dashboard'}
            {router.pathname.startsWith('/credentials') && 'Digital Wallet'}
            {router.pathname.startsWith('/services') && 'Government Services'}
            {router.pathname.startsWith('/activity') && 'Activity History'}
            {router.pathname.startsWith('/settings') && 'Settings'}
          </Typography>

          {/* Theme Toggle */}
          <Tooltip title={`Switch to ${mode === 'light' ? 'dark' : 'light'} mode`}>
            <IconButton color="inherit" onClick={handleThemeToggle}>
              {mode === 'light' ? <Brightness4 /> : <Brightness7 />}
            </IconButton>
          </Tooltip>

          {/* Notifications */}
          <Tooltip title="Notifications">
            <IconButton
              color="inherit"
              onClick={() => setNotificationOpen(true)}
            >
              <Badge badgeContent={unreadCount} color="error">
                <Notifications />
              </Badge>
            </IconButton>
          </Tooltip>

          {/* Profile Menu */}
          <Tooltip title="Profile">
            <IconButton
              onClick={handleProfileMenuOpen}
              sx={{ ml: 1 }}
            >
              <Avatar
                sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}
              >
                {user?.firstName?.[0]}{user?.lastName?.[0]}
              </Avatar>
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      {/* Sidebar Drawer */}
      <Box
        component="nav"
        sx={{ width: { md: sidebarOpen ? DRAWER_WIDTH : 0 }, flexShrink: { md: 0 } }}
      >
        <Drawer
          variant={isMobile ? 'temporary' : 'persistent'}
          open={sidebarOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true, // Better open performance on mobile
          }}
          sx={{
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: DRAWER_WIDTH,
              borderRight: '1px solid',
              borderColor: 'divider',
            },
          }}
        >
          {drawerContent}
        </Drawer>
      </Box>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          width: { md: `calc(100% - ${sidebarOpen ? DRAWER_WIDTH : 0}px)` },
          transition: theme.transitions.create(['width'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar /> {/* Spacer for fixed app bar */}
        
        <AnimatePresence mode="wait">
          <motion.div
            key={router.asPath}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
          >
            {children}
          </motion.div>
        </AnimatePresence>
      </Box>

      {/* Profile Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleProfileMenuClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <MenuItem component={Link} href="/settings/profile" onClick={handleProfileMenuClose}>
          <ListItemIcon><AccountBox /></ListItemIcon>
          Profile
        </MenuItem>
        <MenuItem component={Link} href="/settings/security" onClick={handleProfileMenuClose}>
          <ListItemIcon><Security /></ListItemIcon>
          Security
        </MenuItem>
        <MenuItem component={Link} href="/help" onClick={handleProfileMenuClose}>
          <ListItemIcon><Help /></ListItemIcon>
          Help & Support
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleLogout}>
          <ListItemIcon><Logout /></ListItemIcon>
          Sign Out
        </MenuItem>
      </Menu>

      {/* Notification Panel */}
      <NotificationPanel 
        open={notificationOpen} 
        onClose={() => setNotificationOpen(false)} 
      />
    </Box>
  );
};

export default Layout;