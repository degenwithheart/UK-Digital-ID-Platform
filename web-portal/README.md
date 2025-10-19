# 🌐 Web Portal (TypeScript/Next.js)

Modern dual-portal web application suite providing secure citizen and administrative interfaces for the UK Digital Identity Platform with enterprise-grade architecture.

## 🎯 Features

- **Next.js 14**: Server-side rendering with React 18, TypeScript 5.0, and App Router
- **Dual Portal Architecture**: Dedicated Citizen Portal and Admin Dashboard with role-based access control
- **Real-time Sync**: WebSocket integration for live updates and government feed synchronization
- **Modern Tech Stack**: Tailwind CSS utility-first styling, Framer Motion animations, React Query data fetching
- **Enhanced Security**: JWT authentication, CSP headers, XSS protection, CSRF prevention, input sanitization with DOMPurify
- **Testing & Quality**: Jest unit testing, Cypress E2E testing, Storybook component library, ESLint + Prettier
- **Performance & PWA**: Code splitting, image optimization, service workers, offline capability

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Portal Suite                         │
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────┐         │
│  │   Citizen Portal    │    │  Admin Dashboard    │         │
│  │   (Port 3002)       │    │   (Port 3001)       │         │
│  │ • Registration      │    │ • User Management   │         │
│  │ • Authentication    │    │ • System Monitor    │         │
│  │ • Credential Mgmt   │    │ • Analytics         │         │
│  │ • Verification      │    │ • Audit Logs        │         │
│  │ • Real-time Sync    │    │ • Live Updates      │         │
│  └─────────────────────┘    └─────────────────────┘         │
│           │                           │                     │
│           └───────────────┬───────────┘                     │
│                           │                                 │
│  ┌─────────────────────────▼──────────────────────┐         │
│  │              Next.js 14 Framework               │         │
│  │ • App Router  • SSR/SSG  • TypeScript 5.0      │         │
│  │ • React Query • Zustand  • Tailwind CSS        │         │
│  │ • WebSocket   • CSP      • Real-time Events    │         │
│  └─────────────────────────────────────────────────┘         │
│                           │                                 │
└───────────────────────────┼─────────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │      API Gateway           │
              │    (Go Backend 8081)       │
              └────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   WebSocket Sync Service   │
              │ (Real-time Government Feed)│
              └────────────────────────────┘
```

## 🏢 Portal Applications

| Portal | Port | Target Users | Key Features |
|--------|------|--------------|--------------|
| **Citizen Portal** | 3002 | UK Citizens/Residents | Registration, credential management, verification requests |
| **Admin Dashboard** | 3001 | Government Officials | User management, system monitoring, analytics, audit logs |

## 📦 Technology Stack

| Category | Technologies | Purpose |
|----------|-------------|---------|
| **Framework** | Next.js 14, React 18, TypeScript 5.0 | Modern web application foundation |
| **Styling** | Tailwind CSS, PostCSS, Sass/SCSS | Utility-first responsive design |
| **Animation** | Framer Motion, CSS transitions | Smooth UI interactions |
| **State** | Zustand, React Query (TanStack) | Global state + server state management |
| **Real-time** | WebSocket, Server-Sent Events | Live synchronization and updates |
| **Security** | DOMPurify, CSP Headers, JWT | XSS protection and secure communication |
| **Forms** | React Hook Form, Zod validation | Type-safe form handling |
| **Testing** | Jest, Cypress, React Testing Library | Unit + E2E test coverage |
| **Dev Tools** | Storybook, ESLint, Prettier, Husky | Component library + code quality |

## Applications

### Citizen Portal (Port 3001)
- **Account Management**: Registration, login, profile updates
- **Credential Dashboard**: View and manage digital credentials  
- **Verification History**: Track credential usage and sharing
- **Settings**: Privacy controls and notification preferences

### Admin Dashboard (Port 3000)
- **User Management**: View and moderate citizen accounts
- **Analytics**: Platform usage statistics and trends
- **System Monitoring**: Service health and performance metrics
- **Audit Logs**: Comprehensive activity tracking

## Security Features

### Input Sanitization
```typescript
import DOMPurify from 'dompurify';

const sanitizeInput = (input: string) => DOMPurify.sanitize(input.trim());

// Sanitize all user inputs before processing
const sanitizedEmail = sanitizeInput(formData.email);
```

### Authentication
```typescript
// Secure token storage
localStorage.setItem('authToken', response.data.token);

// Authenticated API calls
const response = await axios.post('/api/endpoint', data, {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest' // CSRF protection
  }
});
```

### Network Security
- **HTTPS Only**: All production requests use TLS encryption
- **Content Security Policy**: CSP headers for XSS prevention and secure resource loading
- **Request Timeouts**: 5-second timeouts prevent hanging requests
- **CORS Headers**: Restricted cross-origin request handling

## API Integration

### Authentication Flow
```typescript
const handleLogin = async (email: string, password: string) => {
  try {
    const response = await axios.post('https://gateway:8080/login', {
      email: sanitizeInput(email),
      password: sanitizeInput(password),
    }, {
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    
    setToken(response.data.token);
    localStorage.setItem('authToken', response.data.token);
    setMessage('Login successful');
  } catch (error) {
    handleApiError(error);
  }
};
```

### Credential Management
```typescript
const fetchCredentials = async () => {
  const token = localStorage.getItem('authToken');
  if (!token) throw new Error('Not authenticated');
  
  const response = await axios.get('/api/credentials', {
    headers: { 'Authorization': `Bearer ${token}` },
    timeout: 5000
  });
  
  return response.data;
};
```

## UI Components

### Reusable Components
- **LoginForm**: Secure authentication form with validation
- **CredentialCard**: Display credential information with actions
- **LoadingSpinner**: Network operation progress indication
- **ErrorBoundary**: Graceful error handling and recovery

### Layout Components
```tsx
// Main layout with navigation
export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation />
      <main className="container mx-auto px-4 py-8">
        {children}
      </main>
      <Footer />
    </div>
  );
}
```

## State Management

### React Hooks
```typescript
// Authentication state
const [token, setToken] = useState<string>('');
const [user, setUser] = useState<User | null>(null);
const [loading, setLoading] = useState<boolean>(false);

// Form state
const [formData, setFormData] = useState({
  email: '',
  password: '',
  name: ''
});
```

### Persistent State
```typescript
// Load authentication state on app start
useEffect(() => {
  const storedToken = localStorage.getItem('authToken');
  if (storedToken) {
    setToken(storedToken);
    fetchUserProfile(storedToken);
  }
}, []);
```

## Responsive Design

### CSS Framework
- **Tailwind CSS**: Utility-first CSS framework
- **Mobile-First**: Progressive enhancement from mobile to desktop
- **Grid Layouts**: CSS Grid for complex layouts
- **Flexbox**: Flexible component arrangements

### Breakpoints
```css
/* Mobile (default) */
.container { padding: 1rem; }

/* Tablet */
@media (min-width: 768px) {
  .container { padding: 2rem; }
}

/* Desktop */
@media (min-width: 1024px) {
  .container { padding: 3rem; }
}
```

## Performance Optimizations

### Next.js Features
- **Server-Side Rendering**: Improved SEO and initial load times
- **Code Splitting**: Automatic route-based code splitting
- **Image Optimization**: Next.js Image component with lazy loading
- **Static Generation**: Pre-built pages for better performance

### Caching Strategies
```typescript
// API response caching
const { data, error } = useSWR('/api/credentials', fetcher, {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  refreshInterval: 30000 // 30 seconds
});
```

## Error Handling

### Global Error Boundary
```tsx
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Application error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return <ErrorFallback onRetry={() => window.location.reload()} />;
    }
    return this.props.children;
  }
}
```

### API Error Handling
```typescript
const handleApiError = (error: any) => {
  if (error.response?.status === 401) {
    // Unauthorized - redirect to login
    localStorage.removeItem('authToken');
    router.push('/login');
  } else if (error.response?.status === 429) {
    setMessage('Too many requests - please try again later');
  } else if (error.code === 'ECONNABORTED') {
    setMessage('Request timeout - please try again');
  } else {
    setMessage(error.response?.data?.error || 'An unexpected error occurred');
  }
};
```

## Building & Deployment

### Development
```bash
npm install              # Install dependencies
npm run dev             # Start development server
npm run lint            # ESLint code analysis
npm run type-check      # TypeScript type checking
```

### Production
```bash
npm run build           # Build production bundle
npm run start          # Start production server
npm run export         # Static export (if applicable)
```

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

## Dependencies

### Core Framework
- **next**: React framework with SSR capabilities
- **react**: UI library for component-based development  
- **typescript**: Type-safe JavaScript development

### UI & Styling
- **tailwindcss**: Utility-first CSS framework
- **@headlessui/react**: Unstyled accessible UI components
- **heroicons**: Beautiful SVG icons

### Networking & Security
- **axios**: HTTP client for API communication
- **dompurify**: XSS protection through HTML sanitization
- **swr**: Data fetching with caching and revalidation

## Testing Strategy

### Unit Testing
```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import LoginForm from '../components/LoginForm';

test('displays error for invalid email', async () => {
  render(<LoginForm />);
  
  const emailInput = screen.getByLabelText('Email');
  const submitButton = screen.getByText('Login');
  
  fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
  fireEvent.click(submitButton);
  
  expect(await screen.findByText('Please enter a valid email')).toBeInTheDocument();
});
```

### Integration Testing
- **API Integration**: Test network request/response handling
- **Authentication Flow**: Test login/logout functionality
- **Form Validation**: Test client-side and server-side validation
- **Error Recovery**: Test error state transitions

## SEO & Accessibility

### Meta Tags
```tsx
import Head from 'next/head';

export default function Page() {
  return (
    <>
      <Head>
        <title>UK Digital ID Platform</title>
        <meta name="description" content="Secure digital identity management" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>
      <main>...</main>
    </>
  );
}
```

### Accessibility Features
- **ARIA Labels**: Screen reader support
- **Keyboard Navigation**: Full keyboard accessibility
- **Color Contrast**: WCAG 2.1 AA compliance
- **Focus Management**: Logical tab order and focus indicators