/**
 * Authentication handlers for email and social login
 * Supports email/password, Google OAuth, and GitHub OAuth
 */

/**
 * Handle email/password login
 * @param {Request} request 
 */
async function handleEmailLogin(request) {
  try {
    const { email, password, context } = await request.json()
    
    if (!email || !password) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Email and password are required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Authenticate with Supabase
    const authResult = await authenticateWithSupabase(email, password)
    
    if (!authResult.success) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: authResult.message || 'Invalid credentials'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Check if user has access to the requested context
    const hasAccess = await checkContextAccess(authResult.user.id, context)
    if (!hasAccess) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'User does not have access to this context'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Generate session token
    const sessionToken = await generateSessionToken(authResult.user, context)

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: authResult.user.id,
        email: authResult.user.email,
        name: authResult.user.name
      },
      context: context,
      token: sessionToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Email login error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Login failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Initiate Google OAuth flow
 * @param {Request} request 
 */
async function handleGoogleOAuth(request) {
  try {
    const url = new URL(request.url)
    const context = url.searchParams.get('context')
    const redirectUri = url.searchParams.get('redirect_uri')

    if (!context) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Context parameter is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const googleAuthUrl = buildGoogleAuthUrl(context, redirectUri)

    return new Response(JSON.stringify({
      authUrl: googleAuthUrl
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Google OAuth init error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'OAuth initialization failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Handle Google OAuth callback
 * @param {Request} request 
 */
async function handleGoogleCallback(request) {
  try {
    const url = new URL(request.url)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')

    if (!code) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Authorization code is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Parse state parameter (contains context and redirect info)
    const stateData = JSON.parse(decodeURIComponent(state || '{}'))
    const context = stateData.context

    // Exchange code for access token
    const tokenResponse = await exchangeGoogleCode(code)
    if (!tokenResponse.success) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Failed to exchange authorization code'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Get user info from Google
    const userInfo = await getGoogleUserInfo(tokenResponse.accessToken)
    if (!userInfo.success) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Failed to get user information'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Create or update user in Supabase
    const user = await createOrUpdateUser({
      email: userInfo.data.email,
      name: userInfo.data.name,
      provider: 'google',
      providerId: userInfo.data.id,
      avatar: userInfo.data.picture
    })

    // Check context access
    const hasAccess = await checkContextAccess(user.id, context)
    if (!hasAccess) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'User does not have access to this context'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Generate session token
    const sessionToken = await generateSessionToken(user, context)

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      },
      context: context,
      token: sessionToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Google OAuth callback error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'OAuth callback failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Initiate GitHub OAuth flow
 * @param {Request} request 
 */
async function handleGitHubOAuth(request) {
  try {
    const url = new URL(request.url)
    const context = url.searchParams.get('context')
    const redirectUri = url.searchParams.get('redirect_uri')

    if (!context) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Context parameter is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const githubAuthUrl = buildGitHubAuthUrl(context, redirectUri)

    return new Response(JSON.stringify({
      authUrl: githubAuthUrl
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('GitHub OAuth init error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'OAuth initialization failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Handle GitHub OAuth callback
 * @param {Request} request 
 */
async function handleGitHubCallback(request) {
  try {
    const url = new URL(request.url)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')

    if (!code) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Authorization code is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Parse state parameter
    const stateData = JSON.parse(decodeURIComponent(state || '{}'))
    const context = stateData.context

    // Exchange code for access token
    const tokenResponse = await exchangeGitHubCode(code)
    if (!tokenResponse.success) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Failed to exchange authorization code'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Get user info from GitHub
    const userInfo = await getGitHubUserInfo(tokenResponse.accessToken)
    if (!userInfo.success) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Failed to get user information'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Create or update user in Supabase
    const user = await createOrUpdateUser({
      email: userInfo.data.email,
      name: userInfo.data.name || userInfo.data.login,
      provider: 'github',
      providerId: userInfo.data.id.toString(),
      avatar: userInfo.data.avatar_url
    })

    // Check context access
    const hasAccess = await checkContextAccess(user.id, context)
    if (!hasAccess) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'User does not have access to this context'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Generate session token
    const sessionToken = await generateSessionToken(user, context)

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      },
      context: context,
      token: sessionToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('GitHub OAuth callback error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'OAuth callback failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Handle user logout
 * @param {Request} request 
 */
async function handleLogout(request) {
  try {
    const authResult = await verifyAuthentication(request)
    
    if (authResult.valid) {
      // Invalidate the session token
      await invalidateSessionToken(authResult.token)
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Logged out successfully'
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Logout error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Logout failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Handle token refresh
 * @param {Request} request 
 */
async function handleTokenRefresh(request) {
  try {
    const authResult = await verifyAuthentication(request)
    
    if (!authResult.valid) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Generate new session token
    const newToken = await generateSessionToken(authResult.user, authResult.context)

    return new Response(JSON.stringify({
      success: true,
      token: newToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Token refresh error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Token refresh failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

// Helper functions for OAuth URL building
function buildGoogleAuthUrl(context, redirectUri) {
  const clientId = GOOGLE_CLIENT_ID // Environment variable
  const scope = 'openid email profile'
  const state = encodeURIComponent(JSON.stringify({ context, redirectUri }))
  const callbackUrl = `${new URL(self.location.href).origin}/auth/callback/google`
  
  return `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${clientId}&` +
    `redirect_uri=${encodeURIComponent(callbackUrl)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent(scope)}&` +
    `state=${state}`
}

function buildGitHubAuthUrl(context, redirectUri) {
  const clientId = GITHUB_CLIENT_ID // Environment variable
  const scope = 'user:email'
  const state = encodeURIComponent(JSON.stringify({ context, redirectUri }))
  const callbackUrl = `${new URL(self.location.href).origin}/auth/callback/github`
  
  return `https://github.com/login/oauth/authorize?` +
    `client_id=${clientId}&` +
    `redirect_uri=${encodeURIComponent(callbackUrl)}&` +
    `scope=${encodeURIComponent(scope)}&` +
    `state=${state}`
}

// Note: OAuth exchange functions and other helper functions will be implemented in separate files