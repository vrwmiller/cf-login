/**
 * Cloudflare Worker for Social and Email Authentication
 * Integrates with Supabase for multi-context user management
 */

// Main event listener for fetch requests
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

/**
 * Main request handler
 * @param {Request} request 
 */
async function handleRequest(request) {
  try {
    const url = new URL(request.url)
    const path = url.pathname

    // Handle preflight OPTIONS requests
    if (request.method === 'OPTIONS') {
      return handleOptionsRequest(request)
    }

    // Add CORS and security headers for all requests
    const response = await routeRequest(request, path)
    return addCorsHeaders(response, request)
  } catch (error) {
    console.error('Error handling request:', error)
    const errorResponse = new Response(JSON.stringify({ 
      error: 'Internal Server Error',
      message: error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
    return addCorsHeaders(errorResponse, request)
  }
}

/**
 * Route requests to appropriate handlers
 * @param {Request} request 
 * @param {string} path 
 */
async function routeRequest(request, path) {
  const method = request.method

  // Health check endpoint
  if (path === '/health' && method === 'GET') {
    return new Response(JSON.stringify({ 
      status: 'ok', 
      timestamp: new Date().toISOString() 
    }), {
      headers: { 'Content-Type': 'application/json' }
    })
  }

  // Authentication endpoints
  if (path.startsWith('/auth/')) {
    return handleAuthRoutes(request, path)
  }

  // User management endpoints
  if (path.startsWith('/user/')) {
    return handleUserRoutes(request, path)
  }

  // Context management endpoints
  if (path.startsWith('/context/')) {
    return handleContextRoutes(request, path)
  }

  // Default response for unmatched routes
  return new Response(JSON.stringify({ 
    error: 'Not Found',
    message: `Route ${path} not found` 
  }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Handle authentication-related routes
 * @param {Request} request 
 * @param {string} path 
 */
async function handleAuthRoutes(request, path) {
  const method = request.method

  switch (path) {
    case '/auth/login/email':
      if (method === 'POST') {
        return handleEmailLogin(request)
      }
      break

    case '/auth/login/google':
      if (method === 'GET') {
        return handleGoogleOAuth(request)
      }
      break

    case '/auth/login/github':
      if (method === 'GET') {
        return handleGitHubOAuth(request)
      }
      break

    case '/auth/callback/google':
      if (method === 'GET') {
        return handleGoogleCallback(request)
      }
      break

    case '/auth/callback/github':
      if (method === 'GET') {
        return handleGitHubCallback(request)
      }
      break

    case '/auth/logout':
      if (method === 'POST') {
        return handleLogout(request)
      }
      break

    case '/auth/refresh':
      if (method === 'POST') {
        return handleTokenRefresh(request)
      }
      break
  }

  return new Response(JSON.stringify({ 
    error: 'Method Not Allowed',
    message: `${method} not allowed for ${path}` 
  }), {
    status: 405,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Handle user-related routes
 * @param {Request} request 
 * @param {string} path 
 */
async function handleUserRoutes(request, path) {
  // Verify authentication for user routes
  const authResult = await verifyAuthentication(request)
  if (!authResult.valid) {
    return new Response(JSON.stringify({ 
      error: 'Unauthorized',
      message: 'Valid authentication required' 
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  const method = request.method

  switch (path) {
    case '/user/profile':
      if (method === 'GET') {
        return getUserProfile(authResult.user)
      }
      if (method === 'PUT') {
        return updateUserProfile(request, authResult.user)
      }
      break

    case '/user/contexts':
      if (method === 'GET') {
        return getUserContexts(authResult.user)
      }
      break
  }

  return new Response(JSON.stringify({ 
    error: 'Method Not Allowed',
    message: `${method} not allowed for ${path}` 
  }), {
    status: 405,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Handle context-related routes
 * @param {Request} request 
 * @param {string} path 
 */
async function handleContextRoutes(request, path) {
  // Verify authentication for context routes
  const authResult = await verifyAuthentication(request)
  if (!authResult.valid) {
    return new Response(JSON.stringify({ 
      error: 'Unauthorized',
      message: 'Valid authentication required' 
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  const method = request.method

  switch (path) {
    case '/context/switch':
      if (method === 'POST') {
        return switchUserContext(request, authResult.user)
      }
      break

    case '/context/current':
      if (method === 'GET') {
        return getCurrentContext(authResult.user)
      }
      break
  }

  return new Response(JSON.stringify({ 
    error: 'Method Not Allowed',
    message: `${method} not allowed for ${path}` 
  }), {
    status: 405,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Add CORS and security headers to response
 * @param {Response} response 
 * @param {Request} request 
 */
function addCorsHeaders(response, request = null) {
  const headers = new Headers(response.headers)
  
  // CORS headers
  const origin = request?.headers.get('Origin')
  const allowedOrigins = getAllowedOrigins()
  
  if (origin && allowedOrigins.includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin)
  } else if (allowedOrigins.includes('*')) {
    headers.set('Access-Control-Allow-Origin', '*')
  }
  
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
  headers.set('Access-Control-Allow-Credentials', 'true')
  headers.set('Access-Control-Max-Age', '86400')
  
  // Security headers
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('X-Frame-Options', 'DENY')
  headers.set('X-XSS-Protection', '1; mode=block')
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  
  // Content Security Policy
  headers.set('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' https://api.supabase.io; " +
    "frame-ancestors 'none';"
  )

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: headers
  })
}

/**
 * Get allowed origins from environment or default
 */
function getAllowedOrigins() {
  // This should come from environment variables
  const allowedOrigins = ALLOWED_ORIGINS || '*'
  return allowedOrigins.split(',').map(origin => origin.trim())
}

/**
 * Handle preflight OPTIONS requests
 * @param {Request} request 
 */
function handleOptionsRequest(request) {
  return addCorsHeaders(new Response(null, { status: 200 }), request)
}

// Placeholder functions - to be implemented in subsequent files
async function handleEmailLogin(request) {
  return new Response(JSON.stringify({ message: 'Email login not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleGoogleOAuth(request) {
  return new Response(JSON.stringify({ message: 'Google OAuth not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleGitHubOAuth(request) {
  return new Response(JSON.stringify({ message: 'GitHub OAuth not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleGoogleCallback(request) {
  return new Response(JSON.stringify({ message: 'Google callback not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleGitHubCallback(request) {
  return new Response(JSON.stringify({ message: 'GitHub callback not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleLogout(request) {
  return new Response(JSON.stringify({ message: 'Logout not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function handleTokenRefresh(request) {
  return new Response(JSON.stringify({ message: 'Token refresh not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function verifyAuthentication(request) {
  return { valid: false, message: 'Authentication verification not yet implemented' }
}

async function getUserProfile(user) {
  return new Response(JSON.stringify({ message: 'Get user profile not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function updateUserProfile(request, user) {
  return new Response(JSON.stringify({ message: 'Update user profile not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function getUserContexts(user) {
  return new Response(JSON.stringify({ message: 'Get user contexts not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function switchUserContext(request, user) {
  return new Response(JSON.stringify({ message: 'Switch user context not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function getCurrentContext(user) {
  return new Response(JSON.stringify({ message: 'Get current context not yet implemented' }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  })
}