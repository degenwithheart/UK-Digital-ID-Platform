import React, { useState } from 'react';
import {
  Drawer,
  Box,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  Chip,
  Button,
  Divider,
  Avatar,
  Badge,
} from '@mui/material';
import {
  Close,
  Notifications,
  Security,
  Info,
  Warning,
  CheckCircle,
  Delete,
  MarkAsRead,
  ClearAll,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useAppSelector, useAppDispatch } from '@/store/hooks';
import { 
  markAsRead, 
  markAllAsRead, 
  removeNotification, 
  clearAllNotifications 
} from '@/store/slices/notificationSlice';
import { formatDistanceToNow } from 'date-fns';

interface NotificationPanelProps {
  open: boolean;
  onClose: () => void;
}

const NotificationPanel: React.FC<NotificationPanelProps> = ({ open, onClose }) => {
  const dispatch = useAppDispatch();
  const { notifications, unreadCount } = useAppSelector((state) => state.notifications);
  const [filter, setFilter] = useState<'all' | 'unread'>('all');

  const filteredNotifications = filter === 'unread' 
    ? notifications.filter(n => !n.read)
    : notifications;

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'success': return <CheckCircle color="success" />;
      case 'error': return <Warning color="error" />;
      case 'warning': return <Warning color="warning" />;
      case 'security': return <Security color="error" />;
      default: return <Info color="info" />;
    }
  };

  const handleMarkAsRead = (id: string) => {
    dispatch(markAsRead(id));
  };

  const handleMarkAllAsRead = () => {
    dispatch(markAllAsRead());
  };

  const handleRemoveNotification = (id: string) => {
    dispatch(removeNotification(id));
  };

  const handleClearAll = () => {
    dispatch(clearAllNotifications());
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: { width: { xs: '100%', sm: 400 } }
      }}
    >
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center">
              <Badge badgeContent={unreadCount} color="error">
                <Notifications />
              </Badge>
              <Typography variant="h6" sx={{ ml: 1 }}>
                Notifications
              </Typography>
            </Box>
            <IconButton onClick={onClose}>
              <Close />
            </IconButton>
          </Box>

          {/* Filter Buttons */}
          <Box display="flex" gap={1} mt={2}>
            <Button
              size="small"
              variant={filter === 'all' ? 'contained' : 'outlined'}
              onClick={() => setFilter('all')}
            >
              All ({notifications.length})
            </Button>
            <Button
              size="small"
              variant={filter === 'unread' ? 'contained' : 'outlined'}
              onClick={() => setFilter('unread')}
            >
              Unread ({unreadCount})
            </Button>
          </Box>

          {/* Action Buttons */}
          {notifications.length > 0 && (
            <Box display="flex" gap={1} mt={2}>
              {unreadCount > 0 && (
                <Button
                  size="small"
                  startIcon={<MarkAsRead />}
                  onClick={handleMarkAllAsRead}
                >
                  Mark all read
                </Button>
              )}
              <Button
                size="small"
                startIcon={<ClearAll />}
                onClick={handleClearAll}
                color="error"
              >
                Clear all
              </Button>
            </Box>
          )}
        </Box>

        {/* Notifications List */}
        <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
          {filteredNotifications.length === 0 ? (
            <Box
              display="flex"
              flexDirection="column"
              alignItems="center"
              justifyContent="center"
              sx={{ height: '100%', p: 3, textAlign: 'center' }}
            >
              <Notifications sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No notifications
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {filter === 'unread' 
                  ? 'You have no unread notifications'
                  : 'All caught up! New notifications will appear here.'
                }
              </Typography>
            </Box>
          ) : (
            <List sx={{ p: 0 }}>
              <AnimatePresence>
                {filteredNotifications.map((notification, index) => (
                  <motion.div
                    key={notification.id}
                    initial={{ opacity: 0, x: 300 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -300 }}
                    transition={{ duration: 0.2, delay: index * 0.05 }}
                  >
                    <ListItem
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        backgroundColor: notification.read ? 'transparent' : 'action.hover',
                        '&:hover': {
                          backgroundColor: 'action.selected',
                        },
                      }}
                    >
                      <ListItemIcon>
                        <Avatar sx={{ width: 32, height: 32 }}>
                          {getNotificationIcon(notification.type)}
                        </Avatar>
                      </ListItemIcon>
                      
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography
                              variant="subtitle2"
                              sx={{
                                fontWeight: notification.read ? 400 : 600,
                                flexGrow: 1,
                              }}
                            >
                              {notification.title}
                            </Typography>
                            {!notification.read && (
                              <Box
                                sx={{
                                  width: 8,
                                  height: 8,
                                  borderRadius: '50%',
                                  backgroundColor: 'primary.main',
                                }}
                              />
                            )}
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="body2" color="text.secondary">
                              {notification.message}
                            </Typography>
                            <Box display="flex" alignItems="center" justifyContent="space-between" mt={0.5}>
                              <Typography variant="caption" color="text.secondary">
                                {formatDistanceToNow(new Date(notification.timestamp), { addSuffix: true })}
                              </Typography>
                              {notification.category && (
                                <Chip
                                  label={notification.category}
                                  size="small"
                                  variant="outlined"
                                  sx={{ fontSize: '0.625rem', height: 20 }}
                                />
                              )}
                            </Box>
                          </Box>
                        }
                      />
                      
                      <ListItemSecondaryAction>
                        <Box display="flex" flexDirection="column" gap={0.5}>
                          {!notification.read && (
                            <IconButton
                              size="small"
                              onClick={() => handleMarkAsRead(notification.id)}
                            >
                              <CheckCircle fontSize="small" />
                            </IconButton>
                          )}
                          <IconButton
                            size="small"
                            onClick={() => handleRemoveNotification(notification.id)}
                          >
                            <Delete fontSize="small" />
                          </IconButton>
                        </Box>
                      </ListItemSecondaryAction>
                    </ListItem>
                  </motion.div>
                ))}
              </AnimatePresence>
            </List>
          )}
        </Box>
      </Box>
    </Drawer>
  );
};

export default NotificationPanel;