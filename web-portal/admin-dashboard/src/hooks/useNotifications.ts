import { useState, useEffect, useCallback } from 'react';

interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  priority: 'low' | 'medium' | 'high' | 'critical';
  category: 'system' | 'security' | 'api' | 'user' | 'audit';
  actionUrl?: string;
  metadata?: Record<string, any>;
}

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  loading: boolean;
  error: string | null;
}

interface NotificationFilters {
  type?: Notification['type'][];
  category?: Notification['category'][];
  priority?: Notification['priority'][];
  read?: boolean;
  dateRange?: {
    start: Date;
    end: Date;
  };
}

export const useNotifications = () => {
  const [state, setState] = useState<NotificationState>({
    notifications: [],
    unreadCount: 0,
    loading: false,
    error: null
  });

  const [filters, setFilters] = useState<NotificationFilters>({});
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);

  // Load notifications from API
  const loadNotifications = useCallback(async (filtersToApply?: NotificationFilters) => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    
    try {
      const queryParams = new URLSearchParams();
      const currentFilters = filtersToApply || filters;
      
      if (currentFilters.type?.length) {
        queryParams.append('type', currentFilters.type.join(','));
      }
      if (currentFilters.category?.length) {
        queryParams.append('category', currentFilters.category.join(','));
      }
      if (currentFilters.priority?.length) {
        queryParams.append('priority', currentFilters.priority.join(','));
      }
      if (typeof currentFilters.read === 'boolean') {
        queryParams.append('read', currentFilters.read.toString());
      }
      if (currentFilters.dateRange) {
        queryParams.append('start', currentFilters.dateRange.start.toISOString());
        queryParams.append('end', currentFilters.dateRange.end.toISOString());
      }

      const response = await fetch(`/api/admin/notifications?${queryParams.toString()}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('admin_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load notifications');
      }

      const data = await response.json();
      
      // Simulate notifications if API is not available
      const mockNotifications: Notification[] = [
        {
          id: '1',
          type: 'error',
          title: 'API Connection Failure',
          message: 'DVLA API is experiencing connectivity issues. Response time exceeded 30 seconds.',
          timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
          read: false,
          priority: 'high',
          category: 'api',
          actionUrl: '/admin/monitoring',
          metadata: { service: 'DVLA', responseTime: 32000 }
        },
        {
          id: '2',
          type: 'warning',
          title: 'High Memory Usage',
          message: 'System memory usage has exceeded 85%. Consider scaling resources.',
          timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
          read: false,
          priority: 'medium',
          category: 'system',
          actionUrl: '/admin/monitoring',
          metadata: { memoryUsage: 87.3, threshold: 85 }
        },
        {
          id: '3',
          type: 'error',
          title: 'Security Alert',
          message: 'Multiple failed login attempts detected from IP 192.168.1.100',
          timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
          read: false,
          priority: 'critical',
          category: 'security',
          actionUrl: '/admin/security',
          metadata: { ip: '192.168.1.100', attempts: 15, blocked: true }
        },
        {
          id: '4',
          type: 'success',
          title: 'System Backup Completed',
          message: 'Daily system backup completed successfully. 15.2GB archived.',
          timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          read: true,
          priority: 'low',
          category: 'system',
          metadata: { backupSize: '15.2GB', duration: '23m 12s' }
        },
        {
          id: '5',
          type: 'info',
          title: 'Government API Update',
          message: 'NHS API has been updated to v2.1. New endpoints available for medical records.',
          timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
          read: true,
          priority: 'medium',
          category: 'api',
          metadata: { service: 'NHS', version: 'v2.1', newEndpoints: 3 }
        },
        {
          id: '6',
          type: 'warning',
          title: 'User Verification Backlog',
          message: '47 user verifications are pending manual review.',
          timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
          read: false,
          priority: 'medium',
          category: 'user',
          actionUrl: '/admin/users?filter=pending',
          metadata: { pendingCount: 47, avgWaitTime: '2.3 hours' }
        },
        {
          id: '7',
          type: 'info',
          title: 'Audit Log Archived',
          message: 'Monthly audit logs have been archived to long-term storage.',
          timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          read: true,
          priority: 'low',
          category: 'audit',
          metadata: { recordsArchived: 1250000, archiveSize: '8.7GB' }
        }
      ];

      const notifications = data.notifications || mockNotifications;
      const unreadCount = notifications.filter((n: Notification) => !n.read).length;

      setState(prev => ({
        ...prev,
        notifications,
        unreadCount,
        loading: false
      }));

    } catch (error) {
      console.error('Error loading notifications:', error);
      setState(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to load notifications',
        loading: false
      }));
    }
  }, [filters]);

  // Mark notification as read
  const markAsRead = useCallback(async (notificationId: string) => {
    try {
      const response = await fetch(`/api/admin/notifications/${notificationId}/read`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('admin_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to mark notification as read');
      }

      setState(prev => ({
        ...prev,
        notifications: prev.notifications.map(n =>
          n.id === notificationId ? { ...n, read: true } : n
        ),
        unreadCount: Math.max(0, prev.unreadCount - 1)
      }));

    } catch (error) {
      console.error('Error marking notification as read:', error);
    }
  }, []);

  // Mark all notifications as read
  const markAllAsRead = useCallback(async () => {
    try {
      const response = await fetch('/api/admin/notifications/read-all', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('admin_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to mark all notifications as read');
      }

      setState(prev => ({
        ...prev,
        notifications: prev.notifications.map(n => ({ ...n, read: true })),
        unreadCount: 0
      }));

    } catch (error) {
      console.error('Error marking all notifications as read:', error);
    }
  }, []);

  // Delete notification
  const deleteNotification = useCallback(async (notificationId: string) => {
    try {
      const response = await fetch(`/api/admin/notifications/${notificationId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('admin_token')}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to delete notification');
      }

      setState(prev => {
        const notification = prev.notifications.find(n => n.id === notificationId);
        const wasUnread = notification && !notification.read;
        
        return {
          ...prev,
          notifications: prev.notifications.filter(n => n.id !== notificationId),
          unreadCount: wasUnread ? Math.max(0, prev.unreadCount - 1) : prev.unreadCount
        };
      });

    } catch (error) {
      console.error('Error deleting notification:', error);
    }
  }, []);

  // Apply filters
  const applyFilters = useCallback((newFilters: NotificationFilters) => {
    setFilters(newFilters);
    loadNotifications(newFilters);
  }, [loadNotifications]);

  // Clear filters
  const clearFilters = useCallback(() => {
    const emptyFilters = {};
    setFilters(emptyFilters);
    loadNotifications(emptyFilters);
  }, [loadNotifications]);

  // Get notifications by category
  const getNotificationsByCategory = useCallback((category: Notification['category']) => {
    return state.notifications.filter(n => n.category === category);
  }, [state.notifications]);

  // Get unread notifications
  const getUnreadNotifications = useCallback(() => {
    return state.notifications.filter(n => !n.read);
  }, [state.notifications]);

  // Get critical notifications
  const getCriticalNotifications = useCallback(() => {
    return state.notifications.filter(n => n.priority === 'critical' && !n.read);
  }, [state.notifications]);

  // Real-time notification subscription
  useEffect(() => {
    if (!realTimeEnabled) return;

    let eventSource: EventSource;
    let reconnectTimeout: NodeJS.Timeout;

    const connectToNotifications = () => {
      const token = localStorage.getItem('admin_token');
      if (!token) return;

      eventSource = new EventSource(`/api/admin/notifications/stream?token=${encodeURIComponent(token)}`);

      eventSource.onmessage = (event) => {
        try {
          const notification: Notification = JSON.parse(event.data);
          
          setState(prev => ({
            ...prev,
            notifications: [notification, ...prev.notifications],
            unreadCount: prev.unreadCount + 1
          }));

          // Show browser notification for critical alerts
          if (notification.priority === 'critical' && 'Notification' in window) {
            Notification.requestPermission().then((permission) => {
              if (permission === 'granted') {
                new Notification(notification.title, {
                  body: notification.message,
                  icon: '/favicon.ico',
                  tag: notification.id
                });
              }
            });
          }

        } catch (error) {
          console.error('Error processing notification:', error);
        }
      };

      eventSource.onerror = (error) => {
        console.error('Notification stream error:', error);
        eventSource.close();
        
        // Reconnect after 5 seconds
        reconnectTimeout = setTimeout(connectToNotifications, 5000);
      };
    };

    connectToNotifications();

    return () => {
      if (eventSource) {
        eventSource.close();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, [realTimeEnabled]);

  // Load initial notifications
  useEffect(() => {
    loadNotifications();
  }, [loadNotifications]);

  return {
    ...state,
    filters,
    realTimeEnabled,
    setRealTimeEnabled,
    loadNotifications,
    markAsRead,
    markAllAsRead,
    deleteNotification,
    applyFilters,
    clearFilters,
    getNotificationsByCategory,
    getUnreadNotifications,
    getCriticalNotifications
  };
};