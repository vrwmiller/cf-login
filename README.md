# Cloudflare Worker Authentication Service

A comprehensive authentication service built as a Cloudflare Worker that supports both email/password and social login (Google, GitHub) with multi-context user management backed by Supabase.

## Features

* **Email/Password Authentication** - Traditional login with Supabase Auth
* **Social Login** - Google and GitHub OAuth integration
* **Multi-Context Support** - Users can access different applications/contexts
* **JWT Session Management** - Secure token-based authentication
* **Security Headers** - CORS, CSP, and other security best practices
* **Edge Performance** - Deployed on Cloudflare's global network
* **Session Storage** - Uses Cloudflare KV for session management

## Architecture

```
Client App → Cloudflare Worker → Supabase Database
                ↓
         OAuth Providers (Google, GitHub)
                ↓
           Cloudflare KV (Sessions)
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login/email` | Email/password login |
| `GET` | `/auth/login/google` | Initiate Google OAuth |
| `GET` | `/auth/login/github` | Initiate GitHub OAuth |
| `GET` | `/auth/callback/google` | Google OAuth callback |
| `GET` | `/auth/callback/github` | GitHub OAuth callback |
| `POST` | `/auth/logout` | Logout user |
| `POST` | `/auth/refresh` | Refresh session token |

### User Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/user/profile` | Get user profile |
| `PUT` | `/user/profile` | Update user profile |
| `GET` | `/user/contexts` | Get user's accessible contexts |

### Context Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/context/switch` | Switch to different context |
| `GET` | `/context/current` | Get current context |

### Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## Database Schema

The following Supabase tables are expected:

### `users` Table
```sql
CREATE TABLE users (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255),
  provider VARCHAR(50) DEFAULT 'email',
  provider_id VARCHAR(255),
  avatar_url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_sign_in_at TIMESTAMPTZ
);
```

### `contexts` Table
```sql
CREATE TABLE contexts (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### `user_contexts` Table
```sql
CREATE TABLE user_contexts (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  context_id VARCHAR(255) REFERENCES contexts(id) ON DELETE CASCADE,
  role VARCHAR(100) DEFAULT 'user',
  permissions JSONB DEFAULT '{}',
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, context_id)
);
```

## Setup Instructions

### 1. Prerequisites

- Cloudflare account with Workers enabled
- Supabase project
- Google OAuth app (optional)
- GitHub OAuth app (optional)

### 2. Supabase Setup

1. Create a new Supabase project
2. Run the SQL schema above in the Supabase SQL editor
3. Enable Row Level Security (RLS) on tables as needed
4. Get your project URL and API keys

### 3. OAuth Setup (Optional)

#### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `https://your-worker.workers.dev/auth/callback/google`

#### GitHub OAuth
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `https://your-worker.workers.dev/auth/callback/github`

### 4. Cloudflare KV Setup

1. Create a KV namespace for sessions:
   ```bash
   wrangler kv:namespace create "SESSION_KV"
   ```
2. Update the namespace ID in `wrangler.toml`

### 5. Environment Variables

Set the following secrets using Wrangler:

```bash
# Required - Supabase configuration
wrangler secret put SUPABASE_ANON_KEY
wrangler secret put SUPABASE_SERVICE_ROLE_KEY

# Required - JWT signing secret
wrangler secret put JWT_SECRET

# Optional - Google OAuth (if using Google login)
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET

# Optional - GitHub OAuth (if using GitHub login)
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
```

Update non-sensitive variables in `wrangler.toml`:
- `SUPABASE_URL`
- `ALLOWED_ORIGINS`

### 6. Deploy

```bash
# Deploy to production
wrangler deploy

# Deploy to staging
wrangler deploy --env staging

# Deploy to development
wrangler deploy --env development
```

## Usage Examples

### Email Login
```javascript
const response = await fetch('https://your-worker.workers.dev/auth/login/email', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123',
    context: 'app1'
  })
});

const data = await response.json();
// Returns: { success: true, user: {...}, token: "jwt-token", context: "app1" }
```

### Social Login (Google)
```javascript
// Step 1: Get OAuth URL
const response = await fetch('https://your-worker.workers.dev/auth/login/google?context=app1');
const { authUrl } = await response.json();

// Step 2: Redirect user to authUrl
window.location.href = authUrl;

// Step 3: Handle callback (automatic)
// User will be redirected back with authentication result
```

### Making Authenticated Requests
```javascript
const token = localStorage.getItem('authToken');

const response = await fetch('https://your-worker.workers.dev/user/profile', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

const profile = await response.json();
```

### Context Switching
```javascript
const response = await fetch('https://your-worker.workers.dev/context/switch', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    contextId: 'app2'
  })
});

const { token: newToken } = await response.json();
// Update stored token with newToken
```

## File Structure

```
cf-login/
├── index.js          # Main Worker script with routing
├── auth.js           # Authentication handlers
├── supabase.js       # Supabase integration
├── session.js        # JWT and session management
├── wrangler.toml     # Wrangler configuration
├── .gitignore        # Git ignore rules
└── README.md         # This file
```

## Security Considerations

- **JWT Secrets**: Use strong, random secrets for JWT signing
- **HTTPS Only**: All endpoints should be accessed via HTTPS
- **CORS Configuration**: Configure allowed origins appropriately
- **Token Expiration**: Tokens expire after 24 hours by default
- **Session Storage**: Sessions are stored in KV with TTL for automatic cleanup
- **Rate Limiting**: Consider implementing rate limiting for login endpoints
- **Input Validation**: All inputs are validated before processing

## Development

### Local Development
Since this is a Cloudflare Worker, use `wrangler dev` for local development:

```bash
wrangler dev
```

### Testing
Test endpoints using curl or your favorite HTTP client:

```bash
# Health check
curl https://your-worker.workers.dev/health

# Email login
curl -X POST https://your-worker.workers.dev/auth/login/email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","context":"app1"}'
```

## Troubleshooting

### Common Issues

1. **KV Namespace Errors**
   - Ensure KV namespace IDs in `wrangler.toml` are correct
   - Verify KV namespaces exist in Cloudflare dashboard

2. **Supabase Connection Issues**
   - Check `SUPABASE_URL` and API keys
   - Verify network connectivity to Supabase

3. **OAuth Redirect Mismatches**
   - Ensure redirect URIs match exactly in OAuth app settings
   - Check for trailing slashes and protocol (https)

4. **CORS Errors**
   - Update `ALLOWED_ORIGINS` in `wrangler.toml`
   - Check that preflight OPTIONS requests are handled

### Logs
Monitor Worker logs in Cloudflare dashboard or via Wrangler:

```bash
wrangler tail
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0). See LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check Cloudflare Workers documentation
- Review Supabase documentation for database-related questions