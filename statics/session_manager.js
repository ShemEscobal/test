/**
 * Session Manager
 * 
 * This module handles authentication, session persistence, and token refreshing
 * for the IoT Dashboard application.
 */

// Self-executing anonymous function to create a module scope
(function() {
    // Session state
    let isAuthenticated = false;
    let username = null;
    let userId = null;
    let isAdmin = false;
    let token = null;
    let tokenExpiry = null;
    
    // Constants
    const TOKEN_REFRESH_INTERVAL = 20 * 60 * 1000; // 20 minutes in milliseconds
    const TOKEN_CHECK_INTERVAL = 60 * 1000; // 1 minute in milliseconds
    
    // Initialize the session manager
    function init() {
        console.log('Initializing session manager...');
        
        // Load session data from localStorage
        loadSessionFromStorage();
        
        // Check current session status with the server
        checkSessionStatus()
            .then(isValid => {
                if (isValid) {
                    console.log('Session validated with server');
                    startTokenRefreshTimer();
                } else {
                    console.warn('Session invalid or expired');
                    if (requiresAuthentication()) {
                        redirectToLogin();
                    }
                }
            })
            .catch(error => {
                console.error('Session check error:', error);
                // Don't automatically redirect on network errors
                // as this could cause login loops when server is unreachable
            });
    }
    
    // Load session data from localStorage
    function loadSessionFromStorage() {
        token = localStorage.getItem('token');
        username = localStorage.getItem('username');
        userId = localStorage.getItem('userId');
        isAdmin = localStorage.getItem('isAdmin') === 'true';
        
        // Parse token expiry if it exists
        const expiryStr = localStorage.getItem('tokenExpiry');
        tokenExpiry = expiryStr ? new Date(expiryStr) : null;
        
        // Set authentication status based on token presence
        isAuthenticated = !!token;
        
        console.log(`Session loaded from storage: ${isAuthenticated ? 'authenticated' : 'not authenticated'}`);
    }
    
    // Check if current page requires authentication
    function requiresAuthentication() {
        const path = window.location.pathname;
        const publicPaths = ['/login', '/login.html', '/register', '/register.html', '/', '/index.html'];
        
        // Check if current path is in public paths
        for (const publicPath of publicPaths) {
            if (path === publicPath || path.endsWith(publicPath)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Check session status with server
    async function checkSessionStatus() {
        try {
            const serverUrl = localStorage.getItem('serverUrl') || window.location.origin;
            const response = await fetch(`${serverUrl}/check-session`, {
                method: 'GET',
                headers: getAuthHeaders(),
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Update session state with server response
                isAuthenticated = data.isAuthenticated || false;
                username = data.username || null;
                userId = data.userId || null;
                isAdmin = data.isAdmin || false;
                
                // If authenticated, persist session data
                if (isAuthenticated) {
                    persistSessionData();
                }
                
                return isAuthenticated;
            }
            
            return false;
        } catch (error) {
            console.error('Error checking session status:', error);
            return false;
        }
    }
    
    // Start token refresh timer
    function startTokenRefreshTimer() {
        // Clear any existing timers
        if (window.tokenRefreshTimer) {
            clearInterval(window.tokenRefreshTimer);
        }
        
        // Set up periodic token refresh
        window.tokenRefreshTimer = setInterval(() => {
            if (isAuthenticated) {
                refreshToken().catch(err => {
                    console.warn('Token refresh failed:', err);
                });
            }
        }, TOKEN_REFRESH_INTERVAL);
        
        console.log('Token refresh timer started');
    }
    
    // Refresh the authentication token
    async function refreshToken() {
        try {
            const serverUrl = localStorage.getItem('serverUrl') || window.location.origin;
            const response = await fetch(`${serverUrl}/refresh-token`, {
                method: 'POST',
                headers: getAuthHeaders(),
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                
                if (data.success) {
                    // Update token and expiry
                    token = data.token;
                    
                    // Calculate token expiry (24 hours from now)
                    const expiry = new Date();
                    expiry.setHours(expiry.getHours() + 24);
                    tokenExpiry = expiry;
                    
                    // Update localStorage
                    persistSessionData();
                    
                    console.log('Token refreshed successfully');
                    return true;
                }
            }
            
            console.warn('Failed to refresh token:', response.status);
            return false;
        } catch (error) {
            console.error('Error refreshing token:', error);
            return false;
        }
    }
    
    // Persist session data to localStorage
    function persistSessionData() {
        if (token) localStorage.setItem('token', token);
        if (username) localStorage.setItem('username', username);
        if (userId) localStorage.setItem('userId', userId);
        localStorage.setItem('isAdmin', isAdmin.toString());
        if (tokenExpiry) localStorage.setItem('tokenExpiry', tokenExpiry.toISOString());
        localStorage.setItem('isLoggedIn', 'true');
    }
    
    // Clear session data
    function clearSession() {
        // Clear session state
        isAuthenticated = false;
        username = null;
        userId = null;
        isAdmin = false;
        token = null;
        tokenExpiry = null;
        
        // Clear localStorage items related to session
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        localStorage.removeItem('userId');
        localStorage.removeItem('isAdmin');
        localStorage.removeItem('tokenExpiry');
        localStorage.removeItem('isLoggedIn');
        
        // Stop token refresh timer
        if (window.tokenRefreshTimer) {
            clearInterval(window.tokenRefreshTimer);
            window.tokenRefreshTimer = null;
        }
    }
    
    // Redirect to login page
    function redirectToLogin() {
        const currentPath = window.location.pathname;
        window.location.href = `/login?redirect=${encodeURIComponent(currentPath)}`;
    }
    
    // Get authentication headers for API requests
    function getAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (token) {
            // The JWT decorator expects either 'token' or 'Bearer token'
            // Let's use the standard Bearer format which is more widely supported
            headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
        }
        
        return headers;
    }
    
    // Check if user is authenticated
    function isUserAuthenticated() {
        return isAuthenticated;
    }
    
    // Get current user details
    function getCurrentUser() {
        return {
            username,
            userId,
            isAdmin
        };
    }
    
    // Handle user logout
    async function logoutUser() {
        try {
            const serverUrl = localStorage.getItem('serverUrl') || window.location.origin;
            
            // Call logout API to clear server-side session
            await fetch(`${serverUrl}/logout`, {
                method: 'GET',
                headers: getAuthHeaders(),
                credentials: 'include'
            });
            
            // Clear client-side session
            clearSession();
            
            // Redirect to login page
            window.location.href = '/login';
            
            return true;
        } catch (error) {
            console.error('Error during logout:', error);
            
            // Even if API call fails, clear local session
            clearSession();
            window.location.href = '/login';
            
            return false;
        }
    }
    
    // Make authenticated API request
    async function fetchWithAuth(url, options = {}) {
        // Add authentication headers
        const headers = { ...getAuthHeaders(), ...(options.headers || {}) };
        
        // Ensure credentials are included
        const fetchOptions = {
            ...options,
            headers,
            credentials: 'include'
        };
        
        try {
            // Make the request
            const response = await fetch(url, fetchOptions);
            
            // Handle 401 Unauthorized (expired/invalid token)
            if (response.status === 401) {
                // Try to refresh token
                const refreshed = await refreshToken();
                
                if (refreshed) {
                    // Update headers with new token
                    fetchOptions.headers = { ...getAuthHeaders(), ...(options.headers || {}) };
                    
                    // Retry request with new token
                    return fetch(url, fetchOptions);
                } else {
                    // Token refresh failed, redirect to login
                    clearSession();
                    redirectToLogin();
                }
            }
            
            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
    
    // Get current user ID from session or localStorage
    function getUserId() {
        // Try multiple sources, in order of reliability
        
        // 1. Session state
        if (isAuthenticated && window.sessionStorage.getItem('userId')) {
            return window.sessionStorage.getItem('userId');
        }
        
        // 2. localStorage
        if (localStorage.getItem('userId')) {
            return localStorage.getItem('userId');
        }
        
        // 3. From current user info if available
        const userData = getCurrentUser();
        if (userData && userData.userId) {
            return userData.userId;
        }
        
        // 4. Last resort: from session username if it exists in localStorage
        const username = sessionStorage.getItem('username') || localStorage.getItem('username');
        if (username) {
            console.log(`Found username ${username}, but no user ID. Session may need refresh.`);
        }
        
        return null;
    }
    
    // Load user devices from the server
    async function loadUserDevices() {
        try {
            // Get the server URL
            const serverUrl = localStorage.getItem('serverUrl') || window.location.origin;

            // Get both user ID and username for the API call
            const userIdValue = getUserId();
            const usernameValue = localStorage.getItem('username');

            if (!userIdValue && !usernameValue) {
                console.log('No user ID or username available for device loading');
                return { devices: [], device_labels: {}, count: 0 };
            }

            // Build query params with both identifiers if available
            let queryParams = [];
            if (userIdValue) queryParams.push(`user_id=${userIdValue}`);
            if (usernameValue) queryParams.push(`username=${usernameValue}`);
            
            const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';

            console.log(`Loading devices for user: ID=${userIdValue}, Username=${usernameValue}`);

            // Make the request with proper authentication
            const response = await fetchWithAuth(`${serverUrl}/api/devices${queryString}`);   

            if (response.ok) {
                const data = await response.json();
                console.log(`Loaded ${data.devices ? data.devices.length : 0} devices from server`);   
                return data;
            } else {
                console.error('Failed to load devices:', response.status);
                
                // If regular endpoint fails, try the debug endpoint as a fallback
                try {
                    console.log('Trying debug endpoint as fallback');
                    let debugQueryParams = [];
                    if (userIdValue) debugQueryParams.push(`user_id=${userIdValue}`);
                    if (usernameValue) debugQueryParams.push(`username=${usernameValue}`);
                    
                    const debugQueryString = debugQueryParams.length > 0 ? `?${debugQueryParams.join('&')}` : '';
                    const debugResponse = await fetchWithAuth(`${serverUrl}/api/debug/get-test-devices${debugQueryString}`);
                    
                    if (debugResponse.ok) {
                        const debugData = await debugResponse.json();
                        console.log(`Loaded ${debugData.devices ? debugData.devices.length : 0} devices from debug endpoint`);
                        return debugData;
                    }
                } catch (debugError) {
                    console.error('Debug endpoint also failed:', debugError);
                }
                
                return { devices: [], device_labels: {}, count: 0 };
            }
        } catch (error) {
            console.error('Error loading user devices:', error);
            return { devices: [], device_labels: {}, count: 0 };
        }
    }
    
    // Initialize on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // Expose public methods to global scope
    window.SessionManager = {
        isAuthenticated: isUserAuthenticated,
        getCurrentUser,
        getAuthHeaders,
        logoutUser,
        fetchWithAuth,
        refreshToken,
        checkSessionStatus,
        loadUserDevices
    };
    
    console.log('Session manager loaded');
})(); 