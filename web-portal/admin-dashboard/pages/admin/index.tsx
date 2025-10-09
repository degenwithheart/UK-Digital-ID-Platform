import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  AppBar,
  Toolbar,
  IconButton,
  Badge,
  Menu,
  MenuList,
  MenuItem as MenuListItem,
  Divider
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  People as PeopleIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  MoreVert as MoreVertIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Analytics as AnalyticsIcon,
  Storage as StorageIcon,
  CloudSync as CloudSyncIcon,
  AdminPanelSettings as AdminIcon,
  SupervisorAccount as SupervisorIcon,
  Shield as ShieldIcon,
  MonitorHeart as MonitorIcon
} from '@mui/icons-material';
import { useAuth } from '../../src/hooks/useAuth';
import { useNotifications } from '../../src/hooks/useNotifications';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index, ...other }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`admin-tabpanel-${index}`}
      aria-labelledby={`admin-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

interface SystemMetrics {
  totalUsers: number;
  activeUsers: number;
  verifications24h: number;
  systemHealth: number;
  apiResponseTime: number;
  errorRate: number;
  storageUsage: number;
  cpuUsage: number;
  memoryUsage: number;
}

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  lastLogin: string;
  verificationLevel: number;
  riskScore: number;
}

interface SecurityAlert {
  id: string;
  type: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  timestamp: string;
  resolved: boolean;
}

interface GovernmentAPIStatus {
  service: string;
  status: 'online' | 'offline' | 'degraded';
  responseTime: number;
  successRate: number;
  lastChecked: string;
}

const AdminDashboard: React.FC = () => {
  const { user, isAdmin, logout } = useAuth();
  const { notifications } = useNotifications();
  const [currentTab, setCurrentTab] = useState(0);
  const [loading, setLoading] = useState(false);
  
  // System State
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>({
    totalUsers: 0,
    activeUsers: 0,
    verifications24h: 0,
    systemHealth: 0,
    apiResponseTime: 0,
    errorRate: 0,
    storageUsage: 0,
    cpuUsage: 0,
    memoryUsage: 0
  });

  const [users, setUsers] = useState<User[]>([]);
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[]>([]);
  const [governmentAPIs, setGovernmentAPIs] = useState<GovernmentAPIStatus[]>([]);
  
  // Dialog States
  const [userDialogOpen, setUserDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  
  // Menu States
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  useEffect(() => {
    if (!isAdmin) {
      window.location.href = '/auth/login';
      return;
    }
    
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
    
    return () => clearInterval(interval);
  }, [isAdmin]);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      // Simulate API calls to load dashboard data
      await Promise.all([
        loadSystemMetrics(),
        loadUsers(),
        loadSecurityAlerts(),
        loadGovernmentAPIStatus()
      ]);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadSystemMetrics = async () => {
    // Simulate real system metrics
    setSystemMetrics({
      totalUsers: 15420,
      activeUsers: 3247,
      verifications24h: 892,
      systemHealth: 98.7,
      apiResponseTime: 145,
      errorRate: 0.23,
      storageUsage: 67.8,
      cpuUsage: 34.2,
      memoryUsage: 56.1
    });
  };

  const loadUsers = async () => {
    // Simulate user data
    const mockUsers: User[] = [
      {
        id: '1',
        email: 'john.doe@example.com',
        name: 'John Doe',
        role: 'citizen',
        status: 'active',
        lastLogin: '2024-01-15T10:30:00Z',
        verificationLevel: 85,
        riskScore: 12
      },
      {
        id: '2',
        email: 'jane.smith@gov.uk',
        name: 'Jane Smith',
        role: 'government_official',
        status: 'active',
        lastLogin: '2024-01-15T09:15:00Z',
        verificationLevel: 95,
        riskScore: 5
      },
      {
        id: '3',
        email: 'admin@system.gov.uk',
        name: 'System Administrator',
        role: 'admin',
        status: 'active',
        lastLogin: '2024-01-15T11:00:00Z',
        verificationLevel: 100,
        riskScore: 0
      }
    ];
    setUsers(mockUsers);
  };

  const loadSecurityAlerts = async () => {
    // Simulate security alerts
    const mockAlerts: SecurityAlert[] = [
      {
        id: '1',
        type: 'medium',
        title: 'Unusual Login Pattern Detected',
        description: 'Multiple failed login attempts from IP 192.168.1.100',
        timestamp: '2024-01-15T10:45:00Z',
        resolved: false
      },
      {
        id: '2',
        type: 'high',
        title: 'Government API Rate Limit Exceeded',
        description: 'DVLA API rate limit exceeded for client ID abc123',
        timestamp: '2024-01-15T10:30:00Z',
        resolved: false
      },
      {
        id: '3',
        type: 'critical',
        title: 'Database Connection Failure',
        description: 'Primary database connection lost for 2 minutes',
        timestamp: '2024-01-15T09:15:00Z',
        resolved: true
      }
    ];
    setSecurityAlerts(mockAlerts);
  };

  const loadGovernmentAPIStatus = async () => {
    // Simulate government API status
    const mockAPIs: GovernmentAPIStatus[] = [
      { service: 'DVLA', status: 'online', responseTime: 120, successRate: 99.8, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'NHS', status: 'online', responseTime: 95, successRate: 99.9, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'DWP', status: 'online', responseTime: 180, successRate: 98.7, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'HMRC', status: 'degraded', responseTime: 450, successRate: 97.2, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Home Office', status: 'online', responseTime: 200, successRate: 99.1, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Companies House', status: 'online', responseTime: 110, successRate: 99.6, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Land Registry', status: 'online', responseTime: 160, successRate: 98.9, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Courts & Tribunals', status: 'online', responseTime: 190, successRate: 99.3, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'DEFRA', status: 'online', responseTime: 140, successRate: 99.0, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Business & Trade', status: 'online', responseTime: 125, successRate: 99.4, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Culture Media Sport', status: 'offline', responseTime: 0, successRate: 0, lastChecked: '2024-01-15T10:30:00Z' },
      { service: 'Energy Security', status: 'online', responseTime: 170, successRate: 98.8, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Housing Communities', status: 'online', responseTime: 155, successRate: 99.2, lastChecked: '2024-01-15T11:00:00Z' },
      { service: 'Science Innovation', status: 'online', responseTime: 135, successRate: 99.5, lastChecked: '2024-01-15T11:00:00Z' }
    ];
    setGovernmentAPIs(mockAPIs);
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'success';
      case 'degraded': return 'warning';
      case 'offline': return 'error';
      default: return 'default';
    }
  };

  const getAlertColor = (type: string) => {
    switch (type) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'info';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 10) return 'success';
    if (score <= 30) return 'warning';
    return 'error';
  };

  const DashboardOverview = () => (
    <Grid container spacing={3}>
      {/* System Metrics Cards */}
      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <PeopleIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="h6">Total Users</Typography>
            </Box>
            <Typography variant="h4" color="primary">
              {systemMetrics.totalUsers.toLocaleString()}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {systemMetrics.activeUsers.toLocaleString()} active today
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <SecurityIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="h6">Verifications</Typography>
            </Box>
            <Typography variant="h4" color="primary">
              {systemMetrics.verifications24h.toLocaleString()}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Last 24 hours
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <MonitorIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="h6">System Health</Typography>
            </Box>
            <Typography variant="h4" color="primary">
              {systemMetrics.systemHealth}%
            </Typography>
            <LinearProgress 
              variant="determinate" 
              value={systemMetrics.systemHealth} 
              color="success"
              sx={{ mt: 1 }}
            />
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <AnalyticsIcon color="primary" sx={{ mr: 1 }} />
              <Typography variant="h6">API Response</Typography>
            </Box>
            <Typography variant="h4" color="primary">
              {systemMetrics.apiResponseTime}ms
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Average response time
            </Typography>
          </CardContent>
        </Card>
      </Grid>

      {/* Security Alerts */}
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Security Alerts
            </Typography>
            {securityAlerts.slice(0, 5).map((alert) => (
              <Alert 
                key={alert.id}
                severity={getAlertColor(alert.type)}
                sx={{ mb: 1 }}
                action={
                  !alert.resolved && (
                    <Button size="small" onClick={() => {}}>
                      Resolve
                    </Button>
                  )
                }
              >
                <Typography variant="subtitle2">{alert.title}</Typography>
                <Typography variant="body2">{alert.description}</Typography>
              </Alert>
            ))}
          </CardContent>
        </Card>
      </Grid>

      {/* Government APIs Status */}
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Government APIs Status ({governmentAPIs.length} Systems)
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Service</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Response Time</TableCell>
                    <TableCell align="right">Success Rate</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {governmentAPIs.slice(0, 8).map((api) => (
                    <TableRow key={api.service}>
                      <TableCell>{api.service}</TableCell>
                      <TableCell>
                        <Chip 
                          label={api.status.toUpperCase()} 
                          color={getStatusColor(api.status)}
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">{api.responseTime}ms</TableCell>
                      <TableCell align="right">{api.successRate}%</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Button 
              fullWidth 
              variant="outlined" 
              sx={{ mt: 2 }}
              onClick={() => setCurrentTab(3)}
            >
              View All {governmentAPIs.length} Government APIs
            </Button>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const UserManagement = () => (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6">User Management</Typography>
        <Button 
          variant="contained" 
          startIcon={<AddIcon />}
          onClick={() => setUserDialogOpen(true)}
        >
          Add User
        </Button>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Email</TableCell>
              <TableCell>Role</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Verification Level</TableCell>
              <TableCell>Risk Score</TableCell>
              <TableCell>Last Login</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id}>
                <TableCell>{user.name}</TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  <Chip 
                    label={user.role.replace('_', ' ').toUpperCase()} 
                    size="small"
                    color={user.role === 'admin' ? 'error' : user.role === 'government_official' ? 'warning' : 'default'}
                  />
                </TableCell>
                <TableCell>
                  <Chip 
                    label={user.status.toUpperCase()} 
                    color={user.status === 'active' ? 'success' : 'error'}
                    size="small" 
                  />
                </TableCell>
                <TableCell>
                  <Box display="flex" alignItems="center">
                    <LinearProgress 
                      variant="determinate" 
                      value={user.verificationLevel} 
                      sx={{ width: 60, mr: 1 }}
                    />
                    <Typography variant="body2">{user.verificationLevel}%</Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip 
                    label={user.riskScore} 
                    color={getRiskScoreColor(user.riskScore)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{new Date(user.lastLogin).toLocaleDateString()}</TableCell>
                <TableCell align="right">
                  <IconButton size="small" onClick={() => setSelectedUser(user)}>
                    <EditIcon />
                  </IconButton>
                  <IconButton size="small" color="error">
                    <BlockIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );

  const SystemMonitoring = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>System Resources</Typography>
            
            <Box mb={2}>
              <Typography variant="body2">CPU Usage</Typography>
              <LinearProgress 
                variant="determinate" 
                value={systemMetrics.cpuUsage} 
                color={systemMetrics.cpuUsage > 80 ? 'error' : systemMetrics.cpuUsage > 60 ? 'warning' : 'success'}
              />
              <Typography variant="caption">{systemMetrics.cpuUsage}%</Typography>
            </Box>

            <Box mb={2}>
              <Typography variant="body2">Memory Usage</Typography>
              <LinearProgress 
                variant="determinate" 
                value={systemMetrics.memoryUsage} 
                color={systemMetrics.memoryUsage > 80 ? 'error' : systemMetrics.memoryUsage > 60 ? 'warning' : 'success'}
              />
              <Typography variant="caption">{systemMetrics.memoryUsage}%</Typography>
            </Box>

            <Box mb={2}>
              <Typography variant="body2">Storage Usage</Typography>
              <LinearProgress 
                variant="determinate" 
                value={systemMetrics.storageUsage} 
                color={systemMetrics.storageUsage > 80 ? 'error' : systemMetrics.storageUsage > 60 ? 'warning' : 'success'}
              />
              <Typography variant="caption">{systemMetrics.storageUsage}%</Typography>
            </Box>

            <Box>
              <Typography variant="body2">Error Rate</Typography>
              <LinearProgress 
                variant="determinate" 
                value={systemMetrics.errorRate * 10} 
                color={systemMetrics.errorRate > 1 ? 'error' : systemMetrics.errorRate > 0.5 ? 'warning' : 'success'}
              />
              <Typography variant="caption">{systemMetrics.errorRate}%</Typography>
            </Box>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Security Monitoring</Typography>
            
            {securityAlerts.map((alert) => (
              <Alert 
                key={alert.id}
                severity={getAlertColor(alert.type)}
                sx={{ mb: 1 }}
                action={
                  <Button size="small" onClick={() => {}}>
                    {alert.resolved ? 'View' : 'Resolve'}
                  </Button>
                }
              >
                <Typography variant="subtitle2">{alert.title}</Typography>
                <Typography variant="body2">{alert.description}</Typography>
                <Typography variant="caption">
                  {new Date(alert.timestamp).toLocaleString()}
                </Typography>
              </Alert>
            ))}
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              All Government APIs Status ({governmentAPIs.length} Systems)
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Service</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="right">Response Time</TableCell>
                    <TableCell align="right">Success Rate</TableCell>
                    <TableCell>Last Checked</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {governmentAPIs.map((api) => (
                    <TableRow key={api.service}>
                      <TableCell>{api.service}</TableCell>
                      <TableCell>
                        <Chip 
                          label={api.status.toUpperCase()} 
                          color={getStatusColor(api.status)}
                          size="small" 
                        />
                      </TableCell>
                      <TableCell align="right">{api.responseTime}ms</TableCell>
                      <TableCell align="right">{api.successRate}%</TableCell>
                      <TableCell>{new Date(api.lastChecked).toLocaleString()}</TableCell>
                      <TableCell align="right">
                        <Button size="small" variant="outlined">
                          Test Connection
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );

  const SystemSettings = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>System Configuration</Typography>
            
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Enable Multi-Factor Authentication"
            />
            
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Real-time Security Monitoring"
            />
            
            <FormControlLabel
              control={<Switch defaultChecked />}
              label="Government API Health Checks"
            />
            
            <FormControlLabel
              control={<Switch />}
              label="Maintenance Mode"
            />
            
            <Box mt={2}>
              <TextField
                fullWidth
                label="Session Timeout (minutes)"
                type="number"
                defaultValue={30}
                variant="outlined"
                size="small"
              />
            </Box>
            
            <Box mt={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Log Level</InputLabel>
                <Select defaultValue="INFO" label="Log Level">
                  <MenuItem value="DEBUG">DEBUG</MenuItem>
                  <MenuItem value="INFO">INFO</MenuItem>
                  <MenuItem value="WARN">WARN</MenuItem>
                  <MenuItem value="ERROR">ERROR</MenuItem>
                </Select>
              </FormControl>
            </Box>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>API Configuration</Typography>
            
            <TextField
              fullWidth
              label="DVLA API Endpoint"
              defaultValue="https://api.dvla.gov.uk/v1"
              variant="outlined"
              size="small"
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              label="NHS API Endpoint"
              defaultValue="https://api.nhs.uk/v1"
              variant="outlined"
              size="small"
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              label="DWP API Endpoint"
              defaultValue="https://api.dwp.gov.uk/v1"
              variant="outlined"
              size="small"
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              label="API Rate Limit (requests/minute)"
              type="number"
              defaultValue={1000}
              variant="outlined"
              size="small"
            />
          </CardContent>
          
          <CardActions>
            <Button variant="contained" color="primary">
              Save Configuration
            </Button>
            <Button variant="outlined">
              Test All APIs
            </Button>
          </CardActions>
        </Card>
      </Grid>
    </Grid>
  );

  if (!isAdmin) {
    return (
      <Container maxWidth="sm" sx={{ mt: 8, textAlign: 'center' }}>
        <Alert severity="error">
          <Typography variant="h6">Access Denied</Typography>
          <Typography>You do not have administrator privileges to access this area.</Typography>
        </Alert>
      </Container>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* Admin Header */}
      <AppBar position="static" color="primary">
        <Toolbar>
          <AdminIcon sx={{ mr: 2 }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Digital ID Platform - Admin Dashboard
          </Typography>
          
          <IconButton color="inherit">
            <Badge badgeContent={securityAlerts.filter(a => !a.resolved).length} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>
          
          <IconButton
            color="inherit"
            onClick={(e) => setAnchorEl(e.currentTarget)}
          >
            <SupervisorIcon />
          </IconButton>
          
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <MenuListItem onClick={() => setSettingsDialogOpen(true)}>
              <SettingsIcon sx={{ mr: 1 }} /> Settings
            </MenuListItem>
            <Divider />
            <MenuListItem onClick={logout}>
              Profile & Logout
            </MenuListItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* Tab Navigation */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={currentTab} onChange={handleTabChange}>
          <Tab icon={<DashboardIcon />} label="Overview" />
          <Tab icon={<PeopleIcon />} label="Users" />
          <Tab icon={<SecurityIcon />} label="Security" />
          <Tab icon={<MonitorIcon />} label="Monitoring" />
          <Tab icon={<SettingsIcon />} label="Settings" />
        </Tabs>
      </Box>

      {/* Tab Panels */}
      <TabPanel value={currentTab} index={0}>
        <DashboardOverview />
      </TabPanel>

      <TabPanel value={currentTab} index={1}>
        <UserManagement />
      </TabPanel>

      <TabPanel value={currentTab} index={2}>
        <Box>
          <Typography variant="h6" gutterBottom>Security Center</Typography>
          {securityAlerts.map((alert) => (
            <Alert 
              key={alert.id}
              severity={getAlertColor(alert.type)}
              sx={{ mb: 2 }}
              action={
                <Button size="small" onClick={() => {}}>
                  {alert.resolved ? 'View Details' : 'Investigate'}
                </Button>
              }
            >
              <Typography variant="subtitle1">{alert.title}</Typography>
              <Typography variant="body2">{alert.description}</Typography>
              <Typography variant="caption">
                {new Date(alert.timestamp).toLocaleString()}
              </Typography>
            </Alert>
          ))}
        </Box>
      </TabPanel>

      <TabPanel value={currentTab} index={3}>
        <SystemMonitoring />
      </TabPanel>

      <TabPanel value={currentTab} index={4}>
        <SystemSettings />
      </TabPanel>

      {/* Loading Overlay */}
      {loading && (
        <Box sx={{ width: '100%', position: 'fixed', top: 0, zIndex: 1000 }}>
          <LinearProgress />
        </Box>
      )}
    </Box>
  );
};

export default AdminDashboard;