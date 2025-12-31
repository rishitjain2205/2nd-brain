// Cookie-based authentication utilities

export const AUTH_COOKIE_NAME = 'catalyst_auth'
export const REMEMBER_ME_DAYS = 30 // Keep logged in for 30 days if "Remember Me" is checked

interface AuthData {
  email: string
  userType: 'student' | 'professor'
  userName?: string
  isAuthenticated: boolean
}

// Set authentication cookie
export function setAuthCookie(data: AuthData, rememberMe: boolean = false) {
  const maxAge = rememberMe ? REMEMBER_ME_DAYS * 24 * 60 * 60 : 24 * 60 * 60 // 30 days or 1 day
  const expires = new Date(Date.now() + maxAge * 1000)

  const cookieValue = JSON.stringify(data)
  document.cookie = `${AUTH_COOKIE_NAME}=${encodeURIComponent(cookieValue)}; path=/; expires=${expires.toUTCString()}; SameSite=Lax`

  // Also store in localStorage for backwards compatibility
  if (typeof window !== 'undefined') {
    localStorage.setItem('userEmail', data.email)
    localStorage.setItem('userType', data.userType)
    localStorage.setItem('isAuthenticated', 'true')
    if (data.userName) {
      localStorage.setItem('userName', data.userName)
    }
  }
}

// Get authentication data from cookie
export function getAuthCookie(): AuthData | null {
  if (typeof document === 'undefined') return null

  const cookies = document.cookie.split(';')
  const authCookie = cookies.find(cookie => cookie.trim().startsWith(`${AUTH_COOKIE_NAME}=`))

  if (!authCookie) return null

  try {
    const cookieValue = authCookie.split('=')[1]
    const data = JSON.parse(decodeURIComponent(cookieValue))
    return data
  } catch (error) {
    return null
  }
}

// Clear authentication cookie
export function clearAuthCookie() {
  document.cookie = `${AUTH_COOKIE_NAME}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`

  // Also clear localStorage
  if (typeof window !== 'undefined') {
    localStorage.removeItem('userEmail')
    localStorage.removeItem('userType')
    localStorage.removeItem('isAuthenticated')
    localStorage.removeItem('userName')
  }
}

// Check if user is authenticated
export function isAuthenticated(): boolean {
  const authData = getAuthCookie()
  return authData?.isAuthenticated || false
}

// Get current user data
export function getCurrentUser(): AuthData | null {
  return getAuthCookie()
}
