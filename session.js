/**
 * Session management with JWT token handling
 * Provides secure token generation, validation, and session management
 */

/**
 * Generate a session token (JWT) for authenticated user
 * @param {Object} user 
 * @param {string} context 
 */
async function generateSessionToken(user, context) {
  try {
    const now = Math.floor(Date.now() / 1000)
    const exp = now + (24 * 60 * 60) // 24 hours expiration

    const payload = {
      sub: user.id,
      email: user.email,
      name: user.name,
      context: context,
      iat: now,
      exp: exp,
      iss: 'cf-login-worker',
      aud: 'cf-login-app'
    }

    // Create JWT token using Web Crypto API
    const token = await createJWT(payload, JWT_SECRET)
    
    // Store session in KV for validation and invalidation
    await storeSession(token, {
      userId: user.id,
      context: context,
      expiresAt: exp,
      createdAt: now
    })

    return token

  } catch (error) {
    console.error('Generate session token error:', error)
    throw new Error('Failed to generate session token')
  }
}

/**
 * Verify authentication from request headers
 * @param {Request} request 
 */
async function verifyAuthentication(request) {
  try {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { valid: false, message: 'Missing or invalid authorization header' }
    }

    const token = authHeader.substring(7) // Remove 'Bearer ' prefix
    
    // Verify JWT token
    const payload = await verifyJWT(token, JWT_SECRET)
    
    if (!payload) {
      return { valid: false, message: 'Invalid token' }
    }

    // Check if token is expired
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
      return { valid: false, message: 'Token expired' }
    }

    // Check if session exists in KV store (for revocation support)
    const sessionExists = await checkSessionExists(token)
    if (!sessionExists) {
      return { valid: false, message: 'Session revoked or not found' }
    }

    return {
      valid: true,
      user: {
        id: payload.sub,
        email: payload.email,
        name: payload.name
      },
      context: payload.context,
      token: token
    }

  } catch (error) {
    console.error('Verify authentication error:', error)
    return { valid: false, message: 'Authentication verification failed' }
  }
}

/**
 * Invalidate a session token
 * @param {string} token 
 */
async function invalidateSessionToken(token) {
  try {
    // Remove from KV store
    await SESSION_KV.delete(`session:${token}`)
    return true

  } catch (error) {
    console.error('Invalidate session token error:', error)
    return false
  }
}

/**
 * Store session information in KV
 * @param {string} token 
 * @param {Object} sessionData 
 */
async function storeSession(token, sessionData) {
  try {
    const expirationTtl = sessionData.expiresAt - Math.floor(Date.now() / 1000)
    
    await SESSION_KV.put(`session:${token}`, JSON.stringify(sessionData), {
      expirationTtl: expirationTtl
    })

  } catch (error) {
    console.error('Store session error:', error)
    throw error
  }
}

/**
 * Check if session exists in KV store
 * @param {string} token 
 */
async function checkSessionExists(token) {
  try {
    const sessionData = await SESSION_KV.get(`session:${token}`)
    return sessionData !== null

  } catch (error) {
    console.error('Check session exists error:', error)
    return false
  }
}

/**
 * Create JWT token using Web Crypto API
 * @param {Object} payload 
 * @param {string} secret 
 */
async function createJWT(payload, secret) {
  const encoder = new TextEncoder()
  
  // Create header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  }

  // Encode header and payload
  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))
  
  // Create signature
  const data = `${encodedHeader}.${encodedPayload}`
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  const encodedSignature = base64urlEncode(signature)
  
  return `${data}.${encodedSignature}`
}

/**
 * Verify JWT token using Web Crypto API
 * @param {string} token 
 * @param {string} secret 
 */
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) {
      return null
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts
    const encoder = new TextEncoder()
    
    // Verify signature
    const data = `${encodedHeader}.${encodedPayload}`
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
    
    const signature = base64urlDecode(encodedSignature)
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data))
    
    if (!isValid) {
      return null
    }

    // Decode and return payload
    const payload = JSON.parse(base64urlDecodeString(encodedPayload))
    return payload

  } catch (error) {
    console.error('Verify JWT error:', error)
    return null
  }
}

/**
 * Base64URL encode (without padding)
 * @param {string|ArrayBuffer} data 
 */
function base64urlEncode(data) {
  let encoded
  if (typeof data === 'string') {
    encoded = btoa(unescape(encodeURIComponent(data)))
  } else {
    // ArrayBuffer
    const bytes = new Uint8Array(data)
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('')
    encoded = btoa(binary)
  }
  
  return encoded
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Base64URL decode to ArrayBuffer
 * @param {string} data 
 */
function base64urlDecode(data) {
  // Add padding if necessary
  const padded = data + '==='.slice((data.length + 3) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  
  return bytes.buffer
}

/**
 * Base64URL decode to string
 * @param {string} data 
 */
function base64urlDecodeString(data) {
  // Add padding if necessary
  const padded = data + '==='.slice((data.length + 3) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  
  return decodeURIComponent(escape(atob(base64)))
}

/**
 * Clean up expired sessions (can be called periodically)
 */
async function cleanupExpiredSessions() {
  try {
    // This would require listing all sessions and checking expiration
    // For now, we rely on KV's built-in TTL expiration
    console.log('Session cleanup - relying on KV TTL expiration')

  } catch (error) {
    console.error('Session cleanup error:', error)
  }
}

/**
 * Get session information from token
 * @param {string} token 
 */
async function getSessionInfo(token) {
  try {
    const sessionData = await SESSION_KV.get(`session:${token}`, 'json')
    return sessionData

  } catch (error) {
    console.error('Get session info error:', error)
    return null
  }
}

/**
 * Extend session expiration
 * @param {string} token 
 * @param {number} additionalSeconds 
 */
async function extendSession(token, additionalSeconds = 24 * 60 * 60) {
  try {
    const sessionData = await getSessionInfo(token)
    if (!sessionData) {
      return false
    }

    const newExpiration = sessionData.expiresAt + additionalSeconds
    const updatedSessionData = {
      ...sessionData,
      expiresAt: newExpiration,
      extendedAt: Math.floor(Date.now() / 1000)
    }

    const expirationTtl = newExpiration - Math.floor(Date.now() / 1000)
    
    await SESSION_KV.put(`session:${token}`, JSON.stringify(updatedSessionData), {
      expirationTtl: expirationTtl
    })

    return true

  } catch (error) {
    console.error('Extend session error:', error)
    return false
  }
}

/**
 * List active sessions for a user (admin function)
 * @param {string} userId 
 */
async function listUserSessions(userId) {
  try {
    // This would require a secondary index in KV or a different storage approach
    // For now, return a placeholder response
    console.log(`Listing sessions for user: ${userId}`)
    return []

  } catch (error) {
    console.error('List user sessions error:', error)
    return []
  }
}

/**
 * Revoke all sessions for a user (security function)
 * @param {string} userId 
 */
async function revokeAllUserSessions(userId) {
  try {
    // This would require listing and deleting all user sessions
    // For now, return a placeholder response
    console.log(`Revoking all sessions for user: ${userId}`)
    return true

  } catch (error) {
    console.error('Revoke all user sessions error:', error)
    return false
  }
}