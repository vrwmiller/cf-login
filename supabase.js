/**
 * Supabase integration for user management and multi-context access control
 * Handles database operations for authentication and authorization
 */

/**
 * Authenticate user with email/password via Supabase Auth
 * @param {string} email 
 * @param {string} password 
 */
async function authenticateWithSupabase(email, password) {
  try {
    const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY
      },
      body: JSON.stringify({
        email: email,
        password: password
      })
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        message: data.error_description || 'Authentication failed'
      }
    }

    return {
      success: true,
      user: {
        id: data.user.id,
        email: data.user.email,
        name: data.user.user_metadata?.name || data.user.email
      },
      accessToken: data.access_token
    }

  } catch (error) {
    console.error('Supabase auth error:', error)
    return {
      success: false,
      message: 'Authentication service unavailable'
    }
  }
}

/**
 * Create or update user in Supabase (for OAuth users)
 * @param {Object} userData 
 */
async function createOrUpdateUser(userData) {
  try {
    // First check if user exists
    const existingUser = await getUserByEmail(userData.email)
    
    if (existingUser) {
      // Update existing user
      const response = await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${existingUser.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
        },
        body: JSON.stringify({
          name: userData.name,
          avatar_url: userData.avatar,
          last_sign_in_at: new Date().toISOString()
        })
      })

      if (!response.ok) {
        throw new Error('Failed to update user')
      }

      return {
        id: existingUser.id,
        email: existingUser.email,
        name: userData.name
      }
    } else {
      // Create new user
      const response = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
        },
        body: JSON.stringify({
          email: userData.email,
          name: userData.name,
          provider: userData.provider,
          provider_id: userData.providerId,
          avatar_url: userData.avatar,
          created_at: new Date().toISOString(),
          last_sign_in_at: new Date().toISOString()
        })
      })

      if (!response.ok) {
        throw new Error('Failed to create user')
      }

      const newUser = await response.json()
      return {
        id: newUser[0].id,
        email: newUser[0].email,
        name: newUser[0].name
      }
    }

  } catch (error) {
    console.error('Create/update user error:', error)
    throw error
  }
}

/**
 * Get user by email from Supabase
 * @param {string} email 
 */
async function getUserByEmail(email) {
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/users?email=eq.${encodeURIComponent(email)}`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    })

    if (!response.ok) {
      throw new Error('Failed to fetch user')
    }

    const users = await response.json()
    return users.length > 0 ? users[0] : null

  } catch (error) {
    console.error('Get user by email error:', error)
    return null
  }
}

/**
 * Check if user has access to a specific context
 * @param {string} userId 
 * @param {string} contextId 
 */
async function checkContextAccess(userId, contextId) {
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/user_contexts?user_id=eq.${userId}&context_id=eq.${contextId}&active=eq.true`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    })

    if (!response.ok) {
      return false
    }

    const access = await response.json()
    return access.length > 0

  } catch (error) {
    console.error('Check context access error:', error)
    return false
  }
}

/**
 * Get all contexts accessible to a user
 * @param {Object} user 
 */
async function getUserContexts(user) {
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/user_contexts?user_id=eq.${user.id}&active=eq.true&select=*,contexts(*)`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    })

    if (!response.ok) {
      throw new Error('Failed to fetch user contexts')
    }

    const userContexts = await response.json()
    const contexts = userContexts.map(uc => ({
      id: uc.contexts.id,
      name: uc.contexts.name,
      description: uc.contexts.description,
      role: uc.role,
      permissions: uc.permissions
    }))

    return new Response(JSON.stringify({
      success: true,
      contexts: contexts
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Get user contexts error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch contexts'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Get user profile information
 * @param {Object} user 
 */
async function getUserProfile(user) {
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${user.id}`, {
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    })

    if (!response.ok) {
      throw new Error('Failed to fetch user profile')
    }

    const users = await response.json()
    const userProfile = users[0]

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: userProfile.id,
        email: userProfile.email,
        name: userProfile.name,
        avatar_url: userProfile.avatar_url,
        created_at: userProfile.created_at,
        last_sign_in_at: userProfile.last_sign_in_at
      }
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Get user profile error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch profile'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Update user profile information
 * @param {Request} request 
 * @param {Object} user 
 */
async function updateUserProfile(request, user) {
  try {
    const { name, avatar_url } = await request.json()

    const response = await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${user.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      },
      body: JSON.stringify({
        name: name,
        avatar_url: avatar_url,
        updated_at: new Date().toISOString()
      })
    })

    if (!response.ok) {
      throw new Error('Failed to update user profile')
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Profile updated successfully'
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Update user profile error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update profile'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Switch user to a different context
 * @param {Request} request 
 * @param {Object} user 
 */
async function switchUserContext(request, user) {
  try {
    const { contextId } = await request.json()

    if (!contextId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Context ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Check if user has access to the new context
    const hasAccess = await checkContextAccess(user.id, contextId)
    if (!hasAccess) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'User does not have access to this context'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Generate new session token with the new context
    const newToken = await generateSessionToken(user, contextId)

    return new Response(JSON.stringify({
      success: true,
      context: contextId,
      token: newToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Switch context error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to switch context'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Get current user context
 * @param {Object} user 
 */
async function getCurrentContext(user) {
  try {
    // This would typically be extracted from the current session token
    // For now, we'll return a placeholder response
    return new Response(JSON.stringify({
      success: true,
      context: user.currentContext || 'default',
      message: 'Current context retrieved successfully'
    }), {
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error('Get current context error:', error)
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to get current context'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

/**
 * Exchange Google authorization code for access token
 * @param {string} code 
 */
async function exchangeGoogleCode(code) {
  try {
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: `${new URL(self.location.href).origin}/auth/callback/google`
      })
    })

    const data = await response.json()

    if (!response.ok) {
      return { success: false, message: data.error_description }
    }

    return {
      success: true,
      accessToken: data.access_token,
      idToken: data.id_token
    }

  } catch (error) {
    console.error('Google code exchange error:', error)
    return { success: false, message: 'Token exchange failed' }
  }
}

/**
 * Get user info from Google API
 * @param {string} accessToken 
 */
async function getGoogleUserInfo(accessToken) {
  try {
    const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    })

    const data = await response.json()

    if (!response.ok) {
      return { success: false, message: 'Failed to get user info' }
    }

    return {
      success: true,
      data: data
    }

  } catch (error) {
    console.error('Google user info error:', error)
    return { success: false, message: 'Failed to get user info' }
  }
}

/**
 * Exchange GitHub authorization code for access token
 * @param {string} code 
 */
async function exchangeGitHubCode(code) {
  try {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code: code
      })
    })

    const data = await response.json()

    if (!response.ok || data.error) {
      return { success: false, message: data.error_description }
    }

    return {
      success: true,
      accessToken: data.access_token
    }

  } catch (error) {
    console.error('GitHub code exchange error:', error)
    return { success: false, message: 'Token exchange failed' }
  }
}

/**
 * Get user info from GitHub API
 * @param {string} accessToken 
 */
async function getGitHubUserInfo(accessToken) {
  try {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'User-Agent': 'Cloudflare-Worker-Auth'
      }
    })

    const data = await response.json()

    if (!response.ok) {
      return { success: false, message: 'Failed to get user info' }
    }

    // Get user email if not public
    if (!data.email) {
      const emailResponse = await fetch('https://api.github.com/user/emails', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'User-Agent': 'Cloudflare-Worker-Auth'
        }
      })

      if (emailResponse.ok) {
        const emails = await emailResponse.json()
        const primaryEmail = emails.find(email => email.primary)
        data.email = primaryEmail ? primaryEmail.email : null
      }
    }

    return {
      success: true,
      data: data
    }

  } catch (error) {
    console.error('GitHub user info error:', error)
    return { success: false, message: 'Failed to get user info' }
  }
}