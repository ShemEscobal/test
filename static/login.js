// Function to get the server URL from localStorage or default to current host
function getServerUrl() {
    // Always use the current origin for API requests if we're on the actual page
    // This helps prevent the localhost prefix issue
    if (window.location.hostname !== '' && window.location.hostname !== 'localhost') {
        return window.location.origin;
    }
    
    // First try to get from localStorage
    const savedUrl = localStorage.getItem("serverUrl");
    if (savedUrl && savedUrl.trim() !== '') {
        // Make sure it's a valid URL format
        try {
            // Check if it has a protocol
            if (!savedUrl.startsWith('http://') && !savedUrl.startsWith('https://')) {
                return 'http://' + savedUrl;
            }
            return savedUrl;
        } catch (e) {
            console.warn("Invalid saved server URL:", e);
        }
    }
    
    // Try to use the current hostname with port 3000 if we're not already on port 3000
    const currentHost = window.location.hostname;
    const currentPort = window.location.port;
    
    if (currentHost && currentHost !== 'localhost' && currentHost !== '127.0.0.1') {
        // If we're on the same machine but not using localhost in the URL
        // This handles when accessing via IP address directly
        if (currentPort === '3000') {
            // Already includes the correct port
            return `${window.location.protocol}//${currentHost}:${currentPort}`;
        } else {
            // Need to specify the API port
            return `${window.location.protocol}//${currentHost}:3000`;
        }
    }
    
    // Default to localhost server otherwise
    return "http://127.0.0.1:3000";
}

// Parse query parameters from URL
function getQueryParams() {
    const params = {};
    const queryString = window.location.search.substring(1);
    const pairs = queryString.split('&');
    
    for (const pair of pairs) {
        const [key, value] = pair.split('=');
        if (key) {
            params[decodeURIComponent(key)] = decodeURIComponent(value || '');
        }
    }
    
    return params;
}

// Test if localhost is reachable with the right protocol
async function testLocalServer() {
    const loginStatusElem = document.getElementById('loginStatus');
    if (loginStatusElem) {
        loginStatusElem.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                Testing server connection...
            </div>
        `;
    }
    
    const urls = [
        "http://localhost:3000/ping",
        "http://127.0.0.1:3000/ping",
        "http://localhost:5000/ping",
        "http://127.0.0.1:5000/ping"
    ];
    
    for (const url of urls) {
        try {
            console.log(`Testing connection to ${url}`);
            const response = await fetch(url, {
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 2000
            });
            
            if (response.ok) {
                console.log(`Connection successful to ${url}`);
                
                // Extract base URL
                const baseUrl = url.substring(0, url.lastIndexOf('/'));
                localStorage.setItem('serverUrl', baseUrl);
                
                if (loginStatusElem) {
                    loginStatusElem.innerHTML = `
                        <div class="alert alert-success">
                            <i class="bi bi-check-circle-fill me-2"></i>
                            Server found at ${baseUrl}
                        </div>
                    `;
                }
                
                const serverUrlInput = document.getElementById('serverUrl');
                if (serverUrlInput) {
                    serverUrlInput.value = baseUrl;
                }
                
                return baseUrl;
            }
        } catch (e) {
            console.log(`Failed to connect to ${url}: ${e.message}`);
        }
    }
    
    if (loginStatusElem) {
        loginStatusElem.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                Cannot connect to server at http://localhost.
                <p class="mt-2 mb-1">Please check:</p>
                <ul>
                    <li>The server is running</li>
                    <li>The server URL is correct in Advanced Settings</li>
                    <li>Your network connection is working</li>
                </ul>
                <div class="mt-2">
                    <button class="btn btn-sm btn-outline-primary" onclick="testLocalServer()">
                        <i class="bi bi-arrow-clockwise me-1"></i>Retry
                    </button>
                </div>
            </div>
        `;
    }
    
    return null;
}

// Handle login process
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe')?.checked || false;
    const loginStatusElem = document.getElementById('loginStatus');
    
    // Get the latest server URL from the input field
    const serverUrlInput = document.getElementById('serverUrl');
    let serverUrl = serverUrlInput && serverUrlInput.value ? serverUrlInput.value.trim() : 'http://localhost:3000';
    
    // Default to localhost if empty
    if (!serverUrl || serverUrl === 'localhost') {
        serverUrl = 'http://localhost:3000';
    } else if (!serverUrl.startsWith('http://') && !serverUrl.startsWith('https://')) {
        serverUrl = 'http://' + serverUrl;
    }
    
    // Make sure we have the port
    if (!serverUrl.includes(':3000') && !serverUrl.includes(':5000')) {
        serverUrl += ':3000';
    }
    
    // Store the server URL in localStorage
    localStorage.setItem('serverUrl', serverUrl);
    console.log(`Using server URL: ${serverUrl}`);
    
    if (!username || !password) {
        if (loginStatusElem) {
            loginStatusElem.innerHTML = '<div class="alert alert-danger">Please enter both username and password</div>';
        }
        return;
    }
    
    // Show loading state
    if (loginStatusElem) {
        loginStatusElem.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                Connecting to ${serverUrl}...
            </div>
        `;
    }
    
    try {
        // Test server connection first
        try {
            console.log(`Testing connection to ${serverUrl}/ping`);
            const pingResponse = await fetch(`${serverUrl}/ping`, { 
                method: 'GET',
                mode: 'cors',
                cache: 'no-cache',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!pingResponse.ok) {
                throw new Error(`Server ping failed with status: ${pingResponse.status}`);
            }
            
            console.log("Server ping successful, proceeding with login");
        } catch (pingError) {
            console.error("Server ping failed:", pingError);
            
            // Try to auto-detect the server
            const detectedServer = await testLocalServer();
            if (detectedServer) {
                serverUrl = detectedServer;
                console.log(`Using auto-detected server: ${serverUrl}`);
            } else {
                if (loginStatusElem) {
                    loginStatusElem.innerHTML = `
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle-fill me-2"></i>
                            Cannot connect to server at ${serverUrl}
                            <p class="mt-2 mb-1">Please check:</p>
                            <ul>
                                <li>The server is running</li>
                                <li>The server URL is correct in Advanced Settings</li>
                                <li>Your network connection is working</li>
                            </ul>
                            <div class="mt-2">
                                <button class="btn btn-sm btn-outline-primary" onclick="testLocalServer()">
                                    <i class="bi bi-arrow-clockwise me-1"></i>Retry
                                </button>
                            </div>
                        </div>
                    `;
                }
                return;
            }
        }
        
        // Proceed with login
        console.log(`Sending login request to ${serverUrl}/login`);
        const response = await fetch(`${serverUrl}/login`, {
            method: 'POST',
            mode: 'cors',
            cache: 'no-cache',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
                serverUrl: 'localhost' // Send the MongoDB server URL (always use localhost for MongoDB)
            })
        });
        
        // Log response status for debugging
        console.log(`Login response status: ${response.status}, ok: ${response.ok}`);
        
        // Handle response
        let data;
        try {
            data = await response.json();
        } catch (parseError) {
            console.error("Error parsing response:", parseError);
            throw new Error("Invalid response from server. Please try again.");
        }
        
        if (!response.ok) {
            console.error("Login failed:", data);
            if (loginStatusElem) {
                loginStatusElem.innerHTML = `<div class="alert alert-danger">${data.message || 'Login failed. Please check your credentials.'}</div>`;
            }
            return;
        }
        
        console.log("Login successful, data received:", data);
        
        // Store authentication data - ensuring we get the actual username from MongoDB
        localStorage.setItem('token', data.token);
        localStorage.setItem('token_expiry', data.expires);
        
        // Ensure we get the username from MongoDB, falling back to what user entered if needed
        const userNameFromMongoDB = data.user || data.username || username;
        console.log("Setting username from MongoDB:", userNameFromMongoDB);
        localStorage.setItem('username', userNameFromMongoDB);
        
        // Fix: store userId from either user_id or userId
        localStorage.setItem('userId', data.user_id || data.userId);
        localStorage.setItem('isLoggedIn', 'true');
        
        // Explicitly log the admin status
        console.log("Admin status from server:", data.isAdmin);
        localStorage.setItem('isadmin', data.isAdmin ? 'true' : 'false');
        
        // For auto-refresh (only in dev/test environments)
        if (rememberMe && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
            // Warning: This is not secure for production, only for local development
            localStorage.setItem('_temp_pass', password);
        }
        
        // For admin users, explicitly call set-admin-session endpoint to ensure proper session
        if (data.isAdmin === true) {
            try {
                console.log("Making additional call to set-admin-session for admin user");
                const sessionResponse = await fetch(`${serverUrl}/set-admin-session`, {
                    method: 'POST',
                    mode: 'cors',
                    cache: 'no-cache',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': data.token
                    },
                    body: JSON.stringify({ token: data.token })
                });
                
                if (sessionResponse.ok) {
                    console.log("Session explicitly set on server");
                } else {
                    console.warn("Could not explicitly set session on server:", sessionResponse.status);
                }
            } catch (sessionError) {
                console.error("Error setting admin session:", sessionError);
                // Continue anyway - the login was successful
            }
        }
        
        // Show success message
        if (loginStatusElem) {
            loginStatusElem.innerHTML = `
                <div class="alert alert-success">
                    Login successful! Welcome, ${userNameFromMongoDB}! Redirecting...
                </div>
            `;
        }
        
        // Handle redirect - IMPORTANT CHANGE: Always redirect admin users to admin_dashboard.html
        const params = getQueryParams();
        let redirectUrl;
        
        if (data.isAdmin === true) {
            // For admin users, directly fetch the admin dashboard with the token to ensure proper handling
            console.log("Admin login detected; handling special admin redirection");
            
            // Show a loading message
            if (loginStatusElem) {
                loginStatusElem.innerHTML = `
                    <div class="alert alert-success">
                        <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        Admin login successful! Loading admin dashboard...
                    </div>
                `;
            }
            
            // Set a redirect timer as a backup if direct fetch doesn't work
            setTimeout(() => {
                window.location.href = `/admin_dashboard_direct?token=${encodeURIComponent(data.token)}`;
            }, 1000);
            
            // Try direct fetch first
            try {
                // Directly fetch the admin dashboard page with the token
                const adminPageResponse = await fetch(`/admin_dashboard_direct?token=${encodeURIComponent(data.token)}`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Authorization': data.token
                    }
                });
                
                // If the response is HTML (not a redirect), replace the current page with it
                if (adminPageResponse.ok) {
                    const html = await adminPageResponse.text();
                    if (html.includes('<html') || html.includes('<!DOCTYPE html>')) {
                        // Replace the entire document with the admin dashboard HTML
                        document.open();
                        document.write(html);
                        document.close();
                        console.log("Admin dashboard loaded via direct fetch");
                        // Cancel the timer since we handled it directly
                        clearTimeout(redirectTimer);
                        return;
                    }
                }
            } catch (e) {
                console.error("Error with direct dashboard fetch:", e);
                // Fall back to redirect approach
            }
            
            // If we got here, the direct fetch didn't work or returned a redirect
            // The setTimeout will handle the redirect after 1 second
            console.log("Falling back to redirect method for admin dashboard");
        } else {
            // For regular users, honor the redirect parameter or default to user.html
            redirectUrl = params.redirect || 'user.html';
            console.log('Regular user, redirecting to:', redirectUrl);
            
            // Redirect with a slight delay to show the success message
            setTimeout(() => {
                window.location.href = redirectUrl;
            }, 1000);
        }
        
    } catch (error) {
        console.error("Login error:", error);
        if (loginStatusElem) {
            loginStatusElem.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    ${error.message || 'Error connecting to server. Please try again.'}
                </div>
            `;
        }
    }
}

// Check if user is already logged in
function checkExistingLogin() {
    const token = localStorage.getItem('token');
    const isLoggedIn = localStorage.getItem('isLoggedIn');
    const isAdmin = localStorage.getItem('isadmin');
    
    if (token && isLoggedIn) {
        // Check if token is expired
        const expiryStr = localStorage.getItem('token_expiry');
        if (expiryStr) {
            try {
                const expiry = new Date(expiryStr);
                const now = new Date();
                
                if (now < expiry) {
                    console.log("User is already logged in with valid token");
                    // Redirect to appropriate dashboard
                    const redirectUrl = isAdmin === 'true' ? 'admin_dashboard.html' : 'user.html';
                    window.location.href = redirectUrl;
                    return;
                } else {
                    console.log("Token expired, clearing login data");
                    // Clear expired token data
                    localStorage.removeItem('token');
                    localStorage.removeItem('token_expiry');
                    localStorage.removeItem('isLoggedIn');
                }
            } catch (e) {
                console.error("Error parsing token expiry:", e);
            }
        }
    }
    
    // Handle error messages from other pages
    displayErrorMessages();
}

// Display error messages from query parameters
function displayErrorMessages() {
    const params = getQueryParams();
    const loginStatusElem = document.getElementById('loginStatus');
    
    if (!loginStatusElem) return;
    
    // Check if this is an initial page load or a redirect
    const isInitialPageLoad = !document.referrer || 
                            document.referrer.includes('login.html') || 
                            !sessionStorage.getItem('hasInteracted');
    
    // Set a flag in sessionStorage to track user interaction
    if (!sessionStorage.getItem('hasInteracted')) {
        sessionStorage.setItem('hasInteracted', 'false');
        document.addEventListener('click', function() {
            sessionStorage.setItem('hasInteracted', 'true');
        });
    }
    
    if (params.error) {
        let message = "An error occurred";
        let shouldDisplay = true;
        
        switch (params.error) {
            case 'session_expired':
                message = "Your session has expired. Please log in again.";
                break;
            case 'auth_failed':
                message = "Authentication failed. Please log in again.";
                break;
            case 'no_token':
                message = "You are not logged in. Please log in to continue.";
                break;
            case 'admin_required':
                // For admin_required, redirect to admin-login.html
                window.location.href = "/admin-login.html";
                return; // Exit early
        }
        
        if (shouldDisplay) {
            loginStatusElem.innerHTML = `<div class="alert alert-warning">${message}</div>`;
        }
    }
}

// Function to test server connectivity
async function testServerConnection(url) {
    try {
        console.log(`Testing connection to: ${url}`);
        const startTime = new Date().getTime();
        
        // Create an abort controller with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // Increased timeout to 5 seconds
        
        // First try with a more verbose logging
        console.log(`Sending fetch request to ${url}/ping`);
        const response = await fetch(`${url}/ping`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            headers: {
                'Content-Type': 'application/json'
            },
            signal: controller.signal
        });
        
        // Clear the timeout
        clearTimeout(timeoutId);
        
        const endTime = new Date().getTime();
        const pingTime = endTime - startTime;
        
        console.log(`Fetch completed. Status: ${response.status}, OK: ${response.ok}`);
        
        // Try to get the response data
        let responseData;
        try {
            responseData = await response.json();
            console.log("Ping response data:", responseData);
        } catch (e) {
            console.warn("Could not parse ping response as JSON:", e);
        }
        
        if (response.ok) {
            console.log(`Connection to ${url} successful! Ping time: ${pingTime}ms`);
            return {
                success: true,
                pingTime,
                status: response.status,
                data: responseData
            };
        } else {
            console.error(`Connection to ${url} failed with status: ${response.status}`);
            return {
                success: false,
                pingTime,
                status: response.status,
                data: responseData
            };
        }
    } catch (error) {
        console.error(`Connection to ${url} error:`, error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Function to diagnose server connection issues
async function diagnoseServerConnection() {
    const loginStatusElem = document.getElementById('loginStatus');
    if (loginStatusElem) {
        loginStatusElem.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                Diagnosing server connection...
            </div>
        `;
    }
    
    // Common server URLs to try
    const servers = [
        "http://192.168.8.142:3000", // Your current server
        getServerUrl(),

        window.location.origin
    ];
    
    // Deduplicate the list
    const uniqueServers = [...new Set(servers)];
    
    // Test each server
    const results = [];
    for (const server of uniqueServers) {
        const result = await testServerConnection(server);
        results.push({
            url: server,
            ...result
        });
        
        // If we found a working server, update the localStorage
        if (result.success) {
            localStorage.setItem('serverUrl', server);
            console.log(`Found working server: ${server}. Updated localStorage.`);
        }
    }
    
    // Get the successful connections
    const successful = results.filter(r => r.success);
    
    // Display results
    if (loginStatusElem) {
        if (successful.length > 0) {
            // Sort by ping time
            successful.sort((a, b) => a.pingTime - b.pingTime);
            const bestServer = successful[0];
            
            loginStatusElem.innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle-fill me-2"></i>
                    Successfully connected to server at ${bestServer.url} (${bestServer.pingTime}ms)
                    <div class="mt-2">
                        <button class="btn btn-sm btn-primary" onclick="window.location.reload()">
                            <i class="bi bi-arrow-clockwise me-1"></i>Reload & Try Again
                        </button>
                    </div>
                </div>
            `;
            
            // Update the server URL field if it exists
            const serverUrlField = document.getElementById('serverUrl');
            if (serverUrlField) {
                serverUrlField.value = bestServer.url;
            }
            
        } else {
            loginStatusElem.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    <strong>Could not connect to any server.</strong>
                    <p class="mb-1 mt-2">Please check:</p>
                    <ul>
                        <li>Make sure the server is running on 192.168.4.6:3000</li>
                        <li>Check your network connection</li>
                        <li>Try updating the server URL in Advanced Settings</li>
                    </ul>
                    <div class="mt-3">
                        <button class="btn btn-sm btn-primary" onclick="diagnoseServerConnection()">
                            <i class="bi bi-arrow-repeat me-1"></i>Try Again
                        </button>
                    </div>
                </div>
            `;
        }
    }
    
    return results;
}

// Reset settings to default
function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to default?')) {
        // Set the default server URL
        localStorage.setItem('serverUrl', 'http://127.0.0.1:3000');
        
        // Update the input field
        const serverUrlInput = document.getElementById('serverUrl');
        if (serverUrlInput) {
            serverUrlInput.value = 'http://127.0.0.1:3000';
        }
        
        // Show confirmation
        alert('Settings have been reset to default values.');
        
        // Test the connection
        testServerConnection('http://127.0.0.1:3000');
    }
}

// Initialize UI elements and event listeners
document.addEventListener('DOMContentLoaded', function() {
    console.log("Login page initialized");
    
    // Set your default server URL first
    if (!localStorage.getItem('serverUrl')) {
        localStorage.setItem('serverUrl', 'http://192.168.4.6:3000');
        console.log("Setting default server URL to http://192.168.4.6:3000");
    }
    
    // Set up login form event handler
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Set up test connection button
    const testConnectionBtn = document.getElementById('testConnection');
    if (testConnectionBtn) {
        testConnectionBtn.addEventListener('click', function() {
            const serverUrl = document.getElementById('serverUrl').value || getServerUrl();
            testServerConnection(serverUrl);
        });
    }
    
    // Set up reset settings button
    const resetSettingsBtn = document.getElementById('resetSettings');
    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', resetSettings);
    }
    
    // Populate server URL from current settings
    const serverUrlInput = document.getElementById('serverUrl');
    if (serverUrlInput) {
        serverUrlInput.value = getServerUrl();
        // Save to localStorage on change or blur
        serverUrlInput.addEventListener('change', function() {
            if (serverUrlInput.value && serverUrlInput.value.trim() !== '') {
                localStorage.setItem('serverUrl', serverUrlInput.value.trim());
            }
        });
        serverUrlInput.addEventListener('blur', function() {
            if (serverUrlInput.value && serverUrlInput.value.trim() !== '') {
                localStorage.setItem('serverUrl', serverUrlInput.value.trim());
            }
        });
    }
    
    // Check if user is already logged in
    checkExistingLogin();
}); 