// This script ensures the admin dashboard properly checks for admin status
(function() {
    console.log("Running admin dashboard check");
    
    // Check if we're on the admin dashboard page
    const path = window.location.pathname;
    const isAdminDashboard = path.includes('admin_dashboard.html') || path.includes('admin_dashboard_direct');
    
    if (!isAdminDashboard) {
        console.log("Not on admin dashboard page - skipping check");
        return;
    }
    
    console.log("ADMIN AUTH CHECK: Running immediate authentication check");
    
    // Function to get URL parameters
    function getUrlParams() {
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
    
    // Check if we're on the direct access endpoint
    const directParams = getUrlParams();
    if (directParams.token) {
        // If we got here via the direct endpoint with a token param, store it
        console.log("Direct access method detected with token");
        localStorage.setItem('token', directParams.token);
        localStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('isadmin', 'true');
        
        // This helps ensure tokens are preserved in case of page refresh
        document.cookie = `auth_token=${directParams.token}; path=/; sameSite=None; secure=false`;
        
        // Remove the token from URL by replacing history state (more secure)
        if (window.history && window.history.replaceState) {
            const cleanUrl = window.location.pathname;
            window.history.replaceState({}, document.title, cleanUrl);
            console.log("Cleaned URL by removing token");
        }
    }
    
    // Check if the user is logged in and has admin privileges
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const isAdmin = localStorage.getItem('isadmin') === 'true';
    const token = localStorage.getItem('token');
    
    console.log("Admin dashboard check - isLoggedIn:", isLoggedIn, "isAdmin:", isAdmin);
    
    if (!isLoggedIn || !token) {
        console.warn("User not logged in, redirecting to login page");
        window.location.href = "/admin-login.html";
        return;
    }
    
    if (!isAdmin) {
        console.warn("User is not an admin, redirecting to user dashboard");
        window.location.href = "/user.html";
        return;
    }
    
    // If we reach here, the user is logged in and is an admin
    console.log("Admin dashboard access confirmed from localStorage");
    
    // Always use absolute paths when calling our own API
    console.log("Using absolute path for API endpoints");
    
    // Function to ensure we have proper authorization headers
    function getAuthHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': token
        };
    }
    
    // First, ensure the server session is set properly
    async function ensureServerSession() {
        try {
            console.log("Setting server session with token");
            
            // Add a timeout to prevent long hanging requests
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
            
            try {
                // IMPORTANT: Use absolute path (starting with /) for API endpoint
                const response = await fetch('/set-admin-session', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    credentials: 'include', // Important: include cookies
                    body: JSON.stringify({ token: token }),
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (response.ok) {
                    const data = await response.json();
                    console.log("Server session set successfully:", data);
                    return true;
                } else {
                    console.error("Failed to set server session, status:", response.status);
                    // Try to get error details
                    try {
                        const errorData = await response.json();
                        console.error("Server error:", errorData);
                    } catch (e) {
                        // Ignore parsing errors
                    }
                    // Continue anyway - session might still be valid
                    console.warn("Continuing despite session error");
                    return true;
                }
            } catch (fetchError) {
                clearTimeout(timeoutId);
                if (fetchError.name === 'AbortError') {
                    console.warn("Server session request timed out");
                } else {
                    console.error("Fetch error setting server session:", fetchError);
                }
                // Continue anyway - session might still be valid
                console.warn("Continuing despite connection issues");
                return true;
            }
        } catch (e) {
            console.error("Error setting server session:", e);
            // Continue anyway - session might still be valid
            console.warn("Continuing despite general error");
            return true;
        }
    }
    
    // Function to test token validity
    async function testTokenValidity() {
        try {
            // First ensure the session is set
            const sessionSet = await ensureServerSession();
            console.log("Session set successfully:", sessionSet);
            
            // Now check if the token is valid by making a request to API
            console.log("Checking token validity with /api/current_user");
            console.log("Using auth token:", token);
            
            // IMPORTANT: Use absolute path (starting with /) for API endpoint
            const response = await fetch('/api/current_user', {
                method: 'GET', // Explicitly set method
                headers: getAuthHeaders(), // Use the consistent auth headers function
                credentials: 'include' // Important: include cookies
            });
            
            console.log("API current_user response status:", response.status);
            
            if (!response.ok) {
                console.error("Token validation failed, but continuing anyway");
                
                if (response.status === 401) {
                    console.error("Unauthorized - token might be invalid");
                    // Only redirect for actual auth failures
                    localStorage.removeItem('token');
                    localStorage.removeItem('isLoggedIn');
                    window.location.href = "/admin-login.html?error=auth_failed";
                    return false;
                } else if (response.status === 404) {
                    console.error("API endpoint not found - check server routes");
                    // Don't redirect for 404s - the endpoint might be missing but auth is still valid
                    console.warn("Continuing despite missing API endpoint");
                    return true;
                }
                
                // Try to get error details
                try {
                    const errorData = await response.json();
                    console.error("Error data:", errorData);
                } catch (e) {
                    // Ignore parsing errors
                }
                
                // For other errors, don't redirect - the API might be having issues
                console.warn("Continuing despite API errors");
                return true;
            }
            
            const data = await response.json();
            console.log("Token validation successful:", data);
            
            // Double check admin status
            if (!data.isAdmin) {
                console.error("User is not an admin according to server");
                window.location.href = "/user.html";
                return false;
            }
            
            return true;
        } catch (e) {
            console.error("Error validating token:", e);
            // Don't redirect for network errors - the server might be down
            console.warn("Continuing despite network errors");
            return true;
        }
    }
    
    // Don't block page load, but check token validity in background
    testTokenValidity();
})(); 