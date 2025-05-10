// Example client-side JWT authentication helpers

// Store JWT token in localStorage
function saveToken(token, expiresAt) {
  localStorage.setItem('authToken', token);
  localStorage.setItem('tokenExpires', expiresAt);
}

// Retrieve JWT token from localStorage
function getToken() {
  return localStorage.getItem('authToken');
}

// Clear stored JWT token (logout)
function clearToken() {
  localStorage.removeItem('authToken');
  localStorage.removeItem('tokenExpires');
}

// Check if token is present and not expired
function isLoggedIn() {
  const token = getToken();
  const expires = localStorage.getItem('tokenExpires');
  
  if (!token || !expires) {
    return false;
  }
  
  // Check if token is expired
  const now = new Date();
  const expiryDate = new Date(expires);
  
  return now < expiryDate;
}

// Parse JWT token to access payload data
function parseToken() {
  const token = getToken();
  
  if (!token) {
    return null;
  }
  
  try {
    // Split token into parts and decode the payload
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    // Base64 decode and parse JSON
    const payload = JSON.parse(atob(parts[1]));
    return payload;
  } catch (error) {
    console.error('Error parsing JWT token:', error);
    return null;
  }
}

// Add JWT token to API request headers
async function fetchWithAuth(url, options = {}) {
  // Check if user is logged in
  if (!isLoggedIn()) {
    // Redirect to login page if not authenticated
    window.location.href = '/login.html';
    return;
  }
  
  // Set up request headers with Authorization
  const headers = options.headers || {};
  headers.Authorization = `Bearer ${getToken()}`;
  
  // Make the API request
  try {
    const response = await fetch(url, {
      ...options,
      headers
    });
    
    // Handle 401 Unauthorized (expired/invalid token)
    if (response.status === 401) {
      // Clear invalid token and redirect to login
      clearToken();
      window.location.href = '/login.html?error=session_expired';
      return;
    }
    
    return response;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}

// Example login function
async function login(username, password) {
  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Save token and other user info
      saveToken(data.token, data.expires);
      // Store user info for the app
      localStorage.setItem('user', JSON.stringify({
        username: data.user,
        userId: data.userId,
        isAdmin: data.isAdmin
      }));
      
      return { success: true, data };
    } else {
      return { success: false, error: data.message };
    }
  } catch (error) {
    console.error('Login failed:', error);
    return { success: false, error: 'Network error. Please try again.' };
  }
}

// Example function to fetch user devices with JWT authentication
async function getUserDevices() {
  try {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user || !user.userId) {
      throw new Error('User information not found');
    }
    
    const response = await fetchWithAuth(`/api/devices?user_id=${user.userId}`);
    
    if (!response) return null; // Redirect happened in fetchWithAuth
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching devices:', error);
    return null;
  }
}

// Example admin function to manage auto-registered devices
async function getAutoRegisteredDevices() {
  try {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user || !user.isAdmin) {
      console.error('Admin privileges required');
      return null;
    }
    
    const response = await fetchWithAuth('/api/auto-registered-devices');
    
    if (!response) return null; // Redirect happened in fetchWithAuth
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching auto-registered devices:', error);
    return null;
  }
}

// Example function to assign auto-registered device to a user
async function assignDeviceToUser(deviceKey, userId) {
  try {
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user || !user.isAdmin) {
      console.error('Admin privileges required');
      return { success: false, error: 'Admin privileges required' };
    }
    
    const response = await fetchWithAuth('/api/auto-registered-devices', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        deviceKey,
        userId
      })
    });
    
    if (!response) return null; // Redirect happened in fetchWithAuth
    
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    console.error('Error assigning device:', error);
    return { success: false, error: 'Request failed' };
  }
} 