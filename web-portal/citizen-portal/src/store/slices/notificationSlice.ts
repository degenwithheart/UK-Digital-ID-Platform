import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// Types
export type NotificationType = 'success' | 'error' | 'warning' | 'info';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  persistent?: boolean;
  actionLabel?: string;
  actionUrl?: string;
  category?: 'system' | 'security' | 'service' | 'update';
}

export interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  showNotifications: boolean;
  settings: {
    enablePush: boolean;
    enableEmail: boolean;
    enableSMS: boolean;
    categories: {
      system: boolean;
      security: boolean;
      service: boolean;
      update: boolean;
    };
  };
}

// Initial state
const initialState: NotificationState = {
  notifications: [],
  unreadCount: 0,
  showNotifications: false,
  settings: {
    enablePush: true,
    enableEmail: true,
    enableSMS: false,
    categories: {
      system: true,
      security: true,
      service: true,
      update: true,
    },
  },
};

// Notification slice
const notificationSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    addNotification: (state, action: PayloadAction<Omit<Notification, 'id' | 'timestamp' | 'read'>>) => {
      const notification: Notification = {
        ...action.payload,
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
      
      // Limit to 100 notifications
      if (state.notifications.length > 100) {
        const removed = state.notifications.splice(100);
        // Adjust unread count for removed notifications
        const removedUnread = removed.filter(n => !n.read).length;
        state.unreadCount = Math.max(0, state.unreadCount - removedUnread);
      }
    },
    
    markAsRead: (state, action: PayloadAction<string>) => {
      const notification = state.notifications.find(n => n.id === action.payload);
      if (notification && !notification.read) {
        notification.read = true;
        state.unreadCount = Math.max(0, state.unreadCount - 1);
      }
    },
    
    markAllAsRead: (state) => {
      state.notifications.forEach(notification => {
        notification.read = true;
      });
      state.unreadCount = 0;
    },
    
    removeNotification: (state, action: PayloadAction<string>) => {
      const index = state.notifications.findIndex(n => n.id === action.payload);
      if (index !== -1) {
        const notification = state.notifications[index];
        if (!notification.read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
        state.notifications.splice(index, 1);
      }
    },
    
    clearAllNotifications: (state) => {
      state.notifications = [];
      state.unreadCount = 0;
    },
    
    clearReadNotifications: (state) => {
      state.notifications = state.notifications.filter(n => !n.read);
    },
    
    toggleNotifications: (state) => {
      state.showNotifications = !state.showNotifications;
    },
    
    setShowNotifications: (state, action: PayloadAction<boolean>) => {
      state.showNotifications = action.payload;
    },
    
    updateNotificationSettings: (state, action: PayloadAction<Partial<NotificationState['settings']>>) => {
      state.settings = { ...state.settings, ...action.payload };
    },
    
    updateCategorySettings: (state, action: PayloadAction<Partial<NotificationState['settings']['categories']>>) => {
      state.settings.categories = { ...state.settings.categories, ...action.payload };
    },
    
    // Bulk actions
    addMultipleNotifications: (state, action: PayloadAction<Array<Omit<Notification, 'id' | 'timestamp' | 'read'>>>) => {
      const newNotifications = action.payload.map(notif => ({
        ...notif,
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
      }));
      
      state.notifications.unshift(...newNotifications);
      state.unreadCount += newNotifications.length;
      
      // Limit to 100 notifications
      if (state.notifications.length > 100) {
        const removed = state.notifications.splice(100);
        const removedUnread = removed.filter(n => !n.read).length;
        state.unreadCount = Math.max(0, state.unreadCount - removedUnread);
      }
    },
    
    // Helper actions for common notification types
    addSuccessNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: Notification = {
        ...action.payload,
        type: 'success',
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
        category: 'system',
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
    },
    
    addErrorNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: Notification = {
        ...action.payload,
        type: 'error',
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
        persistent: true,
        category: 'system',
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
    },
    
    addWarningNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: Notification = {
        ...action.payload,
        type: 'warning',
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
        category: 'security',
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
    },
    
    addInfoNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: Notification = {
        ...action.payload,
        type: 'info',
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        read: false,
        category: 'system',
      };
      
      state.notifications.unshift(notification);
      state.unreadCount += 1;
    },
  },
});

export const {
  addNotification,
  markAsRead,
  markAllAsRead,
  removeNotification,
  clearAllNotifications,
  clearReadNotifications,
  toggleNotifications,
  setShowNotifications,
  updateNotificationSettings,
  updateCategorySettings,
  addMultipleNotifications,
  addSuccessNotification,
  addErrorNotification,
  addWarningNotification,
  addInfoNotification,
} = notificationSlice.actions;

export default notificationSlice.reducer;