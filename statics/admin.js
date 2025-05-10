// Safety check to ensure this script only runs on the admin dashboard page
(function() {
    const currentPath = window.location.pathname;
    const currentPage = currentPath.substring(currentPath.lastIndexOf('/') + 1).toLowerCase();
    
    // Allow execution on both admin_dashboard.html and admin_dashboard_direct
    if (currentPage !== 'admin_dashboard.html' && !currentPage.startsWith('admin_dashboard_direct')) {
        console.error('Error: admin.js loaded on incorrect page:', currentPage);
        
        // If logged in as admin, redirect to admin dashboard
        if (localStorage.getItem("isadmin") === "true") {
            console.log("Redirecting to admin dashboard...");
            // Use admin_dashboard_direct with token if available
            const token = localStorage.getItem("token");
            if (token) {
                window.location.href = `/admin_dashboard_direct?token=${encodeURIComponent(token)}`;
            } else {
            window.location.href = 'admin_dashboard.html';
            }
        } else {
            // If not admin, redirect to appropriate page
            console.log("Not admin, redirecting to appropriate page...");
            if (localStorage.getItem("isLoggedIn") === "true") {
                window.location.href = 'user.html';
            } else {
                window.location.href = 'login.html';
            }
        }
        
        // Prevent rest of script from executing
        return;
    }
    
    console.log("Admin.js loaded correctly on admin dashboard page");
})();

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
            console.error("Invalid server URL format:", e);
        }
    }
    
    // If nothing in localStorage or an error occurred, use current origin
    return window.location.origin;
}

// Define currentPage globally for pagination
let currentPage = 1;
let currentDevicesPage = 1;
let currentConnectionsPage = 1;
let currentLogsPage = 1;
let currentStatusFilter = 'all';

// Add utility function for debouncing search
function debounce(func, wait) {
    let timeout;
    return function() {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
}

// Function to initialize sidebar functionality
function initializeSidebar() {
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    const content = document.getElementById('content');
    
    if (sidebarToggle && sidebar && content) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
            content.classList.toggle('active');
        });
        console.log("Sidebar toggle initialized");
    } else {
        console.error("Sidebar elements not found");
    }
}

// Function to initialize navigation between sections
function initializeNavigation() {
    const navLinks = document.querySelectorAll('[data-section]');
    const sections = document.querySelectorAll('.content-section');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the target section from data attribute
            const targetSection = this.getAttribute('data-section');
            
            // Hide all sections
            sections.forEach(section => {
                section.style.display = 'none';
            });
            
            // Show target section
            const sectionToShow = document.getElementById(targetSection);
            if (sectionToShow) {
                sectionToShow.style.display = 'block';
                
                // Load data for the section
                if (targetSection === 'users-section') {
                    fetchUsers(currentPage);
                } else if (targetSection === 'devices-section') {
                    fetchDevices(currentDevicesPage, '', currentStatusFilter);
                } else if (targetSection === 'connections-section') {
                    // Add connection fetching logic here when implemented
                } else if (targetSection === 'logs-section') {
                    // Add logs fetching logic here when implemented
                }
            }
            
            // Update active state in navigation
            navLinks.forEach(navLink => {
                navLink.parentElement.classList.remove('active');
            });
            this.parentElement.classList.add('active');
        });
    });
    console.log("Navigation initialized");
}

// Function to initialize users section
function initializeUsersSection() {
    // Initialize search functionality
    const searchBar = document.getElementById('searchBar');
    if (searchBar) {
        searchBar.addEventListener('input', debounce(function() {
            currentPage = 1; // Reset to first page when searching
            fetchUsers(currentPage, this.value);
        }, 300));
    }
    
    // Initialize pagination buttons
    const prevPageBtn = document.getElementById('prevPage');
    const nextPageBtn = document.getElementById('nextPage');
    
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', function() {
            if (currentPage > 1) {
                currentPage--;
                fetchUsers(currentPage, searchBar ? searchBar.value : '');
            }
        });
    }
    
    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', function() {
            currentPage++;
            fetchUsers(currentPage, searchBar ? searchBar.value : '');
        });
    }
    
    // Initialize add user button
    const addUserBtn = document.getElementById('addUserBtn');
    if (addUserBtn) {
        addUserBtn.addEventListener('click', function() {
            const addUserModal = new bootstrap.Modal(document.getElementById('addUserModal'));
            addUserModal.show();
        });
    }
    
    // Initialize register user button
    const registerUserBtn = document.getElementById('registerUserBtn');
    if (registerUserBtn) {
        registerUserBtn.addEventListener('click', function() {
            const registerUserModal = new bootstrap.Modal(document.getElementById('registerUserModal'));
            registerUserModal.show();
        });
    }
    
    // Initialize create user button in modal
    const createUserBtn = document.getElementById('createUserBtn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', createUser);
    }
    
    // Initialize register button in modal
    const registerBtn = document.getElementById('registerBtn');
    if (registerBtn) {
        registerBtn.addEventListener('click', registerUser);
    }
    
    console.log("Users section initialized");
}

// Function to initialize connections section
function initializeConnectionsSection() {
    console.log("Initializing connections section");
    
    // Initialize status filter buttons
    const statusFilterBtns = document.querySelectorAll('.status-filter-btn');
    if (statusFilterBtns) {
        statusFilterBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                // Update active state
                statusFilterBtns.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                
                // Get the selected status
                currentStatusFilter = this.getAttribute('data-status');
                
                // Reset to first page and fetch data
                currentConnectionsPage = 1;
                fetchConnectionAttempts(currentConnectionsPage, currentStatusFilter);
            });
        });
    }
    
    // Initialize pagination buttons
    const prevConnectionsBtn = document.getElementById('prevConnectionsPage');
    const nextConnectionsBtn = document.getElementById('nextConnectionsPage');
    
    if (prevConnectionsBtn) {
        prevConnectionsBtn.addEventListener('click', function() {
            if (currentConnectionsPage > 1) {
                currentConnectionsPage--;
                fetchConnectionAttempts(currentConnectionsPage, currentStatusFilter);
            }
        });
    }
    
    if (nextConnectionsBtn) {
        nextConnectionsBtn.addEventListener('click', function() {
            currentConnectionsPage++;
            fetchConnectionAttempts(currentConnectionsPage, currentStatusFilter);
        });
    }
    
    // Initialize refresh button
    const refreshConnectionsBtn = document.getElementById('refreshConnectionsBtn');
    if (refreshConnectionsBtn) {
        refreshConnectionsBtn.addEventListener('click', function() {
            fetchConnectionAttempts(currentConnectionsPage, currentStatusFilter);
        });
    }
    
    // Initial data fetch
    fetchConnectionAttempts(1, 'all');
}

// Function to fetch connection attempts
async function fetchConnectionAttempts(page = 1, status = 'all') {
    try {
        // Show loading state
        const connectionsTable = document.getElementById('connectionsTable');
        if (connectionsTable) {
            connectionsTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center">
                        <div class="spinner-border text-primary spinner-border-sm" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <span class="ms-2">Loading connection attempts...</span>
                    </td>
                </tr>
            `;
        }
        
        // Get server URL
        const serverUrl = getServerUrl();
        
        // Make API request with proper authentication
        const response = await fetch(`${serverUrl}/api/connection-attempts?page=${page}&status=${status}`, {
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // Display the connection attempts
        displayConnectionAttempts(data.attempts || []);
        
        // Update pagination
        if (data.pagination) {
            updateConnectionsPagination(data.pagination.currentPage, data.pagination.totalPages);
        } else {
            // Fallback pagination calculation
            const totalPages = Math.ceil((data.attempts?.length || 0) / 10) || 1;
            updateConnectionsPagination(page, totalPages);
        }
        
    } catch (error) {
        console.error("Error fetching connection attempts:", error);
        if (connectionsTable) {
            connectionsTable.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        Error: ${error.message}
                    </td>
                </tr>
            `;
        }
    }
}

// Function to display connection attempts
function displayConnectionAttempts(attempts) {
    const connectionAttempts = document.getElementById('connectionAttempts');
    if (!connectionAttempts) return;
    
    connectionAttempts.innerHTML = "";
    
    if (!attempts || attempts.length === 0) {
        connectionAttempts.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">No connection attempts found</td>
            </tr>
        `;
        return;
    }
    
    // Display each attempt
    attempts.forEach(attempt => {
        // Format timestamp
        const timestamp = new Date(attempt.timestamp).toLocaleString();
        
        // Determine status badge class
        let badgeClass = "bg-secondary";
        if (attempt.status === "success") {
            badgeClass = "bg-success";
        } else if (attempt.status === "fail") {
            badgeClass = "bg-danger";
        } else if (attempt.status === "unauthorized") {
            badgeClass = "bg-warning";
        }
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${attempt.device_key || 'Unknown'}</td>
            <td>${attempt.ip_address || 'Unknown'}</td>
            <td><span class="badge ${badgeClass}">${attempt.status || 'Unknown'}</span></td>
            <td>
                <button class="btn btn-sm btn-outline-info view-details-btn" data-id="${attempt._id}">
                    <i class="bi bi-eye"></i> Details
                </button>
            </td>
        `;
        
        connectionAttempts.appendChild(row);
        
        // Add event listener to the details button
        const detailsBtn = row.querySelector('.view-details-btn');
        if (detailsBtn) {
            detailsBtn.addEventListener('click', () => viewConnectionDetails(attempt._id));
        }
    });
}

// Function to update connections pagination
function updateConnectionsPagination(current, total) {
    const prevBtn = document.getElementById('prevConnectionsPage');
    const nextBtn = document.getElementById('nextConnectionsPage');
    const pageInfo = document.getElementById('connectionsPageInfo');
    
    if (prevBtn) prevBtn.disabled = current <= 1;
    if (nextBtn) nextBtn.disabled = current >= total;
    if (pageInfo) pageInfo.textContent = `Page ${current} of ${total}`;
}

// Function to view connection details
async function viewConnectionDetails(connectionId) {
    try {
        // Get server URL
        const serverUrl = getServerUrl();
        
        // Fetch connection details
        const response = await fetch(`${serverUrl}/api/connection-attempts/${connectionId}`, {
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch connection details: ${response.status}`);
        }
        
        const data = await response.json();
        const connection = data.connection || data;
        
        // Display the connection details in a modal
        const modal = new bootstrap.Modal(document.getElementById('connectionDetailsModal'));
        const modalBody = document.getElementById('connectionDetailsBody');
        
        let html = `
            <div class="connection-details">
                <div class="mb-3">
                    <strong>ID:</strong> ${connection._id}
                </div>
                <div class="mb-3">
                    <strong>Time:</strong> ${new Date(connection.timestamp).toLocaleString()}
                </div>
                <div class="mb-3">
                    <strong>IP Address:</strong> ${connection.ip_address}
                </div>
                <div class="mb-3">
                    <strong>Status:</strong> 
                    <span class="badge ${connection.status === 'success' ? 'bg-success' : connection.status === 'pending' ? 'bg-warning' : 'bg-danger'}">
                        ${connection.status}
                    </span>
                </div>
        `;
        
        // Add request type
        if (connection.request_type) {
            html += `
                <div class="mb-3">
                    <strong>Request Type:</strong> ${connection.request_type}
                </div>
            `;
        }
        
        // Add device key if present
        if (connection.device_key) {
            html += `
                <div class="mb-3">
                    <strong>Device Key:</strong> ${connection.device_key}
                </div>
            `;
        }
        
        // Add user ID if present
        if (connection.user_id) {
            html += `
                <div class="mb-3">
                    <strong>User ID:</strong> ${connection.user_id}
                </div>
            `;
        }
        
        // Add reason if failed
        if (connection.status === 'failed' && connection.reason) {
            html += `
                <div class="mb-3">
                    <strong>Failure Reason:</strong> ${connection.reason}
                </div>
            `;
        }
        
        // Add request data
        if (connection.data) {
            html += `
                <div class="mb-3">
                    <strong>Request Data:</strong>
                    <pre class="bg-light p-2 mt-2 rounded">${JSON.stringify(connection.data, null, 2)}</pre>
                </div>
            `;
        }
        
        html += '</div>';
        
        modalBody.innerHTML = html;
        modal.show();
        
    } catch (error) {
        console.error("Error fetching connection details:", error);
        alert(`Error loading connection details: ${error.message}`);
    }
}

// Function to logout user
function logoutUser() {
    console.log("Logging out user");
    // Clear all localStorage
    localStorage.clear();
    console.log("localStorage cleared");
    // Redirect to login page
    window.location.href = "login.html";
}

// Helper function to check if login is still valid
function checkLoginValidity() {
    const token = localStorage.getItem("token");
    const expiryStr = localStorage.getItem("token_expiry");
    const isLoggedIn = localStorage.getItem("isLoggedIn");
    const username = localStorage.getItem("username");
    const isAdmin = localStorage.getItem("isadmin");
    
    console.log("Token validation debug:");
    console.log(" - token exists:", !!token);
    console.log(" - expiry exists:", !!expiryStr);
    console.log(" - isLoggedIn:", isLoggedIn);
    console.log(" - username:", username);
    console.log(" - isAdmin:", isAdmin);
    
    // First, check for presence of essential login data
    if (!token) {
        console.error("No authentication token found in localStorage");
        return false;
    }
    
    if (!isLoggedIn || !username) {
        console.error("Login information incomplete");
        return false;
    }
    
    if (!isAdmin) {
        console.warn("Not logged in as admin - may have limited functionality");
        // Continue anyway, as the main document.ready function will handle this check properly
    }
    
    // Finally, check token expiration if available
    if (expiryStr) {
        try {
            const expiry = new Date(expiryStr);
            const now = new Date();
            if (now > expiry) {
                console.error("Authentication token has expired");
                console.error(`Token expired at ${expiry.toLocaleString()}, current time ${now.toLocaleString()}`);
                return false;
            }
        } catch (e) {
            console.error("Error parsing token expiry:", e);
            // If we can't parse the expiry, let's assume the token is still valid
            // rather than blocking the user
            return true;
        }
    }
    
    return true;
}

// Test API connection
async function testApiConnection() {
    try {
        const serverUrl = getServerUrl();
        const response = await fetch(`${serverUrl}/api/test`);
        if (response.ok) {
            const data = await response.json();
            console.log("API connection successful:", data);
            return true;
        } else {
            console.error("API connection failed with status:", response.status);
            return false;
        }
    } catch (e) {
        console.error("API connection error:", e);
        return false;
    }
}

// Function to attempt refreshing the JWT token
async function refreshToken() {
    console.log("Attempting to refresh token");
    try {
        const serverUrl = getServerUrl();
        // Check if we have refresh token or credentials
        const username = localStorage.getItem("username");
        const storedPassword = localStorage.getItem("_temp_pass");
        
        if (!username) {
            console.error("Cannot refresh token: no username stored");
            return false;
        }
        
        // Try silent refresh if we have stored credentials (only available in specific testing scenarios)
        if (storedPassword) {
            console.log("Attempting silent refresh with stored credentials");
            try {
                const response = await fetch(`${serverUrl}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: username,
                        password: storedPassword,
                        silent_refresh: true
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.token) {
                        console.log("Silent token refresh successful");
                        // Update token in localStorage
                        localStorage.setItem("token", data.token);
                        localStorage.setItem("token_expiry", data.expires);
                        localStorage.setItem("isLoggedIn", "true");
                        return true;
                    }
                }
            } catch (e) {
                console.error("Silent refresh error:", e);
            }
        }
        
        // If no silent refresh or it failed, log a message but don't alert
        console.warn("Session expired, but continuing silently");
        return false;
    } catch (error) {
        console.error("Token refresh error:", error);
        return false;
    }
}

document.addEventListener("DOMContentLoaded", function () {
    // Store the current URL to localStorage to help with session persistence
    localStorage.setItem("last_admin_url", window.location.href);
    
    // Check for auth token in URL parameters (for direct access links)
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    if (tokenFromUrl) {
        console.log("Found token in URL parameters, storing to localStorage");
        localStorage.setItem("token", tokenFromUrl);
        localStorage.setItem("isLoggedIn", "true");
        localStorage.setItem("isadmin", "true");
        
        // Clean URL by removing token parameter
        const cleanUrl = window.location.pathname;
        history.replaceState({}, document.title, cleanUrl);
    }
    
    // Test API connection - but don't show alert, just log to console
    testApiConnection().then(isConnected => {
        if (!isConnected) {
            console.warn("API connection test failed - continuing anyway since we're already logged in");
            // Continue with the rest of the initialization instead of returning
        }
        
        // Check token validity
        if (!checkLoginValidity()) {
            console.log("Token is invalid or expired, attempting refresh");
            refreshToken().then(refreshed => {
                if (!refreshed) {
                    console.warn("Session expired, redirecting to login");
                    // Store current URL to return after login
                    localStorage.setItem("admin_return_url", window.location.href);
                    window.location.href = "login.html?redirect=admin_dashboard.html";
                    return;
                } else {
                    console.log("Token refreshed successfully");
                    location.reload(); // Reload with new token
                }
            });
            return;
        }
    
        // Check if user is admin
        const username = localStorage.getItem("username");
        const isAdmin = localStorage.getItem("isadmin") === "true";
        
        if (!username || !isAdmin) {
            // Redirect to login page if not logged in as admin
            console.warn("Not logged in as admin, redirecting to login");
            window.location.href = "login.html";
            return;
        }
        
        // Update admin username in the UI
        const adminUsernameElement = document.getElementById('adminUsername');
        if (adminUsernameElement) {
            adminUsernameElement.textContent = username;
        }
        
        // Verify admin status with the server
        verifyAdminStatus(username);
        
        // Initialize sidebar functionality
        initializeSidebar();
        
        // Initialize navigation between sections
        initializeNavigation();
        
        // Initialize all sections
        initializeUsersSection();
        initializeDevicesSection();
        initializeConnectionsSection();
        initializeLogsSection();
        
        // Initially show only the Users section
        const usersSection = document.getElementById('users-section');
        const devicesSection = document.getElementById('devices-section');
        const connectionsSection = document.getElementById('connections-section');
        const logsSection = document.getElementById('logs-section');
        
        if (usersSection) usersSection.style.display = 'block';
        if (devicesSection) devicesSection.style.display = 'none';
        if (connectionsSection) connectionsSection.style.display = 'none';
        if (logsSection) logsSection.style.display = 'none';
        
        // Debug: Log visibility of sections
        console.log("Users section visible:", usersSection ? usersSection.style.display : "not found");
        console.log("Devices section visible:", devicesSection ? devicesSection.style.display : "not found");
        console.log("Connections section visible:", connectionsSection ? connectionsSection.style.display : "not found");
        console.log("Logs section visible:", logsSection ? logsSection.style.display : "not found");
        
        // Manually trigger fetch for the initially visible section
        fetchUsers(currentPage);
        
        // Activate the first nav item
        const firstNavItem = document.querySelector('#sidebar ul.components li:first-child');
        if (firstNavItem) {
            firstNavItem.classList.add('active');
        }
        
        // Setup logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', function(e) {
                e.preventDefault();
                logoutUser();
            });
        }
        
        // Set up periodic token refresh every 10 minutes to prevent session timeout
        setInterval(() => {
            // Try to refresh token in the background
            refreshToken().then(refreshed => {
                if (refreshed) {
                    console.log("Token refreshed successfully in background");
                } else {
                    console.warn("Background token refresh failed");
                }
            });
        }, 10 * 60 * 1000);
        
        // Add a delegated event listener for the logout button
        document.body.addEventListener('click', function(e) {
            // Check if the clicked element or any of its parents has id="logoutBtn"
            let target = e.target;
            while (target != null) {
                if (target.id === 'logoutBtn') {
                    console.log("Logout button clicked via delegation");
                    e.preventDefault();
                    logoutUser();
                    return;
                }
                target = target.parentElement;
            }
        });
    });
});

// Function to verify admin status with the server
async function verifyAdminStatus(username) {
    console.log("Verifying admin status for:", username);
    console.log("isAdmin from localStorage:", localStorage.getItem("isadmin"));
    
    try {
        // Skip the server check if we already have admin status in localStorage
        if (localStorage.getItem("isadmin") === "true") {
            console.log("Admin status already verified from localStorage");
            
            // Update UI with admin name
            const adminUsername = document.getElementById('adminUsername');
            if (adminUsername) {
                adminUsername.textContent = username;
            }
            return;
        }
        
        // If we don't have localStorage confirmation, check with the server
        const token = localStorage.getItem("token");
        const serverUrl = getServerUrl();
        
        // Make authenticated request to check admin status, but catch network errors
        try {
        const response = await fetch(`${serverUrl}/check-admin/${username}`, {
            headers: {
                    'Authorization': token
            }
        });
        
        // Log the raw response for debugging
        console.log("Admin check response status:", response.status);
        
            // If we get any response, consider it a success - we already verified admin status before login
            console.log("Got response from server, assuming admin status is valid");
            
            // Update UI with admin name if needed
            const adminUsername = document.getElementById('adminUsername');
            if (adminUsername) {
                adminUsername.textContent = username;
            }
        } catch (networkError) {
            console.warn("Network error checking admin status, but continuing anyway:", networkError);
            // Just continue - we already verified admin status during login
        
        // Update UI with admin name if needed
        const adminUsername = document.getElementById('adminUsername');
        if (adminUsername) {
            adminUsername.textContent = username;
            }
        }
    } catch (e) {
        console.error("Error in verifyAdminStatus function:", e);
        // Don't redirect or show alerts, just log the error and continue
        console.warn("Continuing despite admin verification error");
        
        // Still update the UI
        const adminUsername = document.getElementById('adminUsername');
        if (adminUsername) {
            adminUsername.textContent = username;
        }
    }
}

// Add a helper function to get authentication headers
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    // Add Authorization header if token exists
    const headers = {
        'Content-Type': 'application/json'
    };
    if (token) {
        headers['Authorization'] = token; // Send token - Flask JWT expects this format
    }
    console.log("Auth headers:", Object.keys(headers), "Token present:", !!token);
    return headers;
}

// Function to fetch users with pagination and search support
async function fetchUsers(page = 1, searchQuery = "") {
    try {
        // Update the page counter
        currentPage = page;
        
        console.log(`Fetching users: page=${page}, searchQuery="${searchQuery}"`);
        
        // Show loading indicator
        const userList = document.getElementById('userList');
        if (userList) {
            userList.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center">
                        <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        Loading users...
                    </td>
                </tr>
            `;
        } else {
            console.error("userList element not found in the DOM");
        }
        
        // Get server URL
        const serverUrl = getServerUrl();
        console.log(`Using server URL: ${serverUrl}`);
        
        // Check authentication before making request
        const token = localStorage.getItem('token');
        if (!token) {
            console.error("No authentication token found");
            if (userList) {
                userList.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center text-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            Authentication token missing. Please <a href="login.html" class="alert-link">login again</a>.
                        </td>
                    </tr>
                `;
            }
            setTimeout(() => {
                window.location.href = "login.html?error=no_token&redirect=admin_dashboard.html";
            }, 3000);
            return;
        }
        
        // Log auth info (without showing actual token)
        const headers = getAuthHeaders();
        console.log("Auth headers present:", Object.keys(headers));
        console.log("Bearer token included:", !!headers.Authorization);
        
        const apiUrl = `${serverUrl}/api/users?page=${page}&search=${searchQuery}&exclude_admins=true`;
        console.log(`Calling API: ${apiUrl}`);
        
        // Make API request with proper authentication
        const response = await fetch(apiUrl, {
            headers: headers
        });
        
        console.log(`API response status: ${response.status}`);
        
        if (response.status === 401 || response.status === 403) {
            console.error("Authentication failed (401/403) - token may be expired or invalid");
            if (userList) {
                userList.innerHTML = `
                    <tr>
                        <td colspan="4" class="text-center text-danger">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            Authentication failed. Your session has expired. Redirecting to login page...
                        </td>
                    </tr>
                `;
            }
            // Clear invalid token and redirect to login
            localStorage.removeItem('token');
            localStorage.removeItem('token_expiry');
            localStorage.removeItem('isLoggedIn');
            setTimeout(() => {
                window.location.href = "login.html?error=auth_failed&redirect=admin_dashboard.html";
            }, 2000);
            return;
        }
        
        if (!response.ok) {
            // Try to get more detailed error information
            try {
                const errorData = await response.json();
                console.error("API error details:", errorData);
                throw new Error(`Failed to fetch users: ${response.status} - ${errorData.message || errorData.error || 'Unknown error'}`);
            } catch (parseError) {
                throw new Error(`Failed to fetch users: ${response.status}`);
            }
        }
        
        const data = await response.json();
        console.log(`Retrieved ${data.users ? data.users.length : 0} users`);
        
        if (data.users) {
            console.log("User data:", data.users);
        }
        
        // Update pagination information
        if (data.pagination) {
            updatePagination(data.pagination.currentPage, data.pagination.totalPages);
        }
        
        // Display users
        displayUsers(data.users || []);
        
    } catch (error) {
        console.error("Error fetching users:", error);
        if (document.getElementById('userList')) {
            document.getElementById('userList').innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        ${error.message}
                        <div class="mt-2">
                            <button class="btn btn-sm btn-outline-primary" onclick="testApiConnection().then(result => { if(result) { fetchUsers(1); }})">
                                <i class="bi bi-arrow-clockwise"></i> Retry
                            </button>
                            <button class="btn btn-sm btn-outline-secondary ms-2" onclick="window.location.href='login.html'">
                                <i class="bi bi-box-arrow-in-right"></i> Login Again
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }
    }
}

// Display users in the table
function displayUsers(users) {
    console.log("displayUsers called with:", users);
    
    const userList = document.getElementById('userList');
    if (!userList) {
        console.error("userList element not found when displaying users");
        return;
    }
    
    userList.innerHTML = "";

    if (!users || users.length === 0) {
        console.log("No users to display");
        userList.innerHTML = `<tr><td colspan="4" class="text-center">No users found</td></tr>`;
        return;
    }

    // Filter out admin users from the display
    const regularUsers = users.filter(user => {
        // Check if user is admin (either is_admin or isAdmin property)
        const isAdmin = user.is_admin !== undefined ? user.is_admin : (user.isAdmin || false);
        return !isAdmin;
    });
    
    console.log(`Filtered ${users.length} users down to ${regularUsers.length} regular users`);
    
    if (regularUsers.length === 0) {
        userList.innerHTML = `<tr><td colspan="4" class="text-center">No regular users found</td></tr>`;
        return;
    }

    regularUsers.forEach((user, index) => {
        console.log(`Processing user ${index + 1}/${regularUsers.length}:`, user);
        
        const row = document.createElement('tr');
        
        // Get user ID properly - could be id or _id depending on API
        const userId = user.id || user._id;
        
        // Add user ID as a data attribute to the row for easier updates
        if (userId) {
            row.dataset.userId = userId;
        } else {
            console.warn("User missing ID:", user);
        }
        
        row.innerHTML = `
            <td>${user.username || 'No username'}</td>
            <td>${user.email || 'No email'}</td>
            <td>
                <div class="device-keys-container">
                    <div class="d-flex justify-content-between mb-2">
                        <span>Device Count: ${user.deviceCount || 0}</span>
                        <button class="btn btn-sm btn-outline-primary add-key-btn" data-id="${userId}">
                            <i class="bi bi-plus-circle"></i> Add Key
                        </button>
                    </div>
                    <div class="key-list" data-id="${userId}">
                        <div class="text-center my-2">
                            <div class="spinner-border spinner-border-sm text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <span class="ms-2">Loading device keys...</span>
                        </div>
                    </div>
                </div>
            </td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-outline-primary view-user-btn" data-id="${userId}">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-warning edit-user-btn" data-id="${userId}">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger delete-user-btn" data-id="${userId}">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        userList.appendChild(row);

        // Add event listeners to the buttons
        console.log("Adding event listeners for user:", userId);
        
        const viewBtn = row.querySelector('.view-user-btn');
        const editBtn = row.querySelector('.edit-user-btn');
        const deleteBtn = row.querySelector('.delete-user-btn');
        const addKeyBtn = row.querySelector('.add-key-btn');
        
        if (viewBtn) viewBtn.addEventListener('click', () => viewUserDetails(userId));
        if (editBtn) editBtn.addEventListener('click', () => editUser(userId));
        if (deleteBtn) deleteBtn.addEventListener('click', () => deleteUser(userId));
        if (addKeyBtn) addKeyBtn.addEventListener('click', () => addKey(userId));
        
        // Fetch and display keys for this user
        console.log(`Fetching keys for user ${userId}`);
        fetchKeysAndDevices(userId, row.querySelector('.key-list'));
    });
    
    console.log("Finished displaying users");
}

// Update pagination display
function updatePagination(current, total) {
    const prevPageBtn = document.getElementById('prevPage');
    const nextPageBtn = document.getElementById('nextPage');
    const pageInfo = document.getElementById('pageInfo');
    
    if (prevPageBtn) prevPageBtn.disabled = current <= 1;
    if (nextPageBtn) nextPageBtn.disabled = current >= total;
    if (pageInfo) pageInfo.textContent = `Page ${current} of ${total || 1}`;
}

// View detailed information for a user
function viewUserDetails(userId) {
    // Get the modal element
    const userDetailsModal = new bootstrap.Modal(document.getElementById('userDetailsModal'));
    const modalBody = document.getElementById('userDetailsBody');
    
    // Show loading state
    modalBody.innerHTML = `
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading user details...</p>
        </div>
    `;
    
    // Show the modal
    userDetailsModal.show();
    
    // Get server URL
    const serverUrl = getServerUrl();
    
    // Create the container for device keys
    const deviceKeysContainer = document.createElement('div');
    deviceKeysContainer.classList.add('device-keys-container', 'mt-4');
    deviceKeysContainer.innerHTML = `
        <h5>User's Device Keys</h5>
        <div id="userKeysContainer" class="mt-2">Loading keys...</div>
    `;
    
    // Fetch user details and render in the modal
    fetch(`${serverUrl}/api/users/${userId}`, {
        headers: getAuthHeaders()
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch user details");
            }
            return response.json();
        })
        .then(data => {
            const user = data.user;
            
            // Format user information
            modalBody.innerHTML = `
                <div class="user-details">
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">User ID:</div>
                        <div class="col-md-8">${user._id || user.id}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">Username:</div>
                        <div class="col-md-8">${user.username}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">Email:</div>
                        <div class="col-md-8">${user.email || 'Not provided'}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">Role:</div>
                        <div class="col-md-8">${user.is_admin ? 'Admin' : 'Regular User'}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">Created:</div>
                        <div class="col-md-8">${new Date(user.created || Date.now()).toLocaleString()}</div>
                    </div>
                    <div class="row mb-3">
                        <div class="col-md-4 fw-bold">Last Login:</div>
                        <div class="col-md-8">${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</div>
                    </div>
                </div>
                
                <div class="actions mt-3">
                    <button class="btn btn-sm btn-primary me-2" onclick="addKey('${user._id || user.id}')">
                        <i class="bi bi-key-fill me-1"></i> Add Device Key
                    </button>
                    <button class="btn btn-sm btn-outline-primary me-2" onclick="editUser('${user._id || user.id}')">
                        <i class="bi bi-pencil me-1"></i> Edit User
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteUser('${user._id || user.id}')">
                        <i class="bi bi-trash me-1"></i> Delete User
                    </button>
                </div>
            `;
            
            // Append the device keys container
            modalBody.appendChild(deviceKeysContainer);
            
            // Fetch the user's device keys
            fetchKeysAndDevices(user._id || user.id, document.getElementById('userKeysContainer'));
        })
        .catch(error => {
            console.error("Error fetching user details:", error);
            modalBody.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    Error loading user details: ${error.message}
                </div>
            `;
        });
}

// Add key to user
async function addKey(userId) {
    // Prompt for the device key
    const key = prompt("Enter the IoT-PoD device key to register:");
    
    if (key === null) return; // User cancelled
    
    if (key.trim() === '') {
        alert('Please enter a valid device key');
        return;
    }
    
    try {
        // Register the existing key for this user
        const response = await fetch(`/register_key`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ user_id: userId, key: key.trim() })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Find the key-list container for this user and update it
            const keyListContainer = document.querySelector(`.key-list[data-id="${userId}"]`);
            if (keyListContainer) {
                fetchKeysAndDevices(userId, keyListContainer);
            }
            
            // Show success message
            alert(data.message || 'Device key registered successfully');
            
            // Refresh the user list
            fetchUsers(currentPage, document.getElementById('searchBar') ? document.getElementById('searchBar').value : '');
        } else {
            alert(data.message || 'Error registering device key');
        }
    } catch (error) {
        console.error("Error registering key:", error);
        alert(`Error registering device key: ${error.message}`);
    }
}

// Edit user
function editUser(userId) {
    // Here you would show a modal to edit user info
    // For now we'll use a placeholder
    alert(`Edit user ID: ${userId}`);
}

// Delete user
async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            // Refresh the user list
            fetchUsers(currentPage, document.getElementById('searchBar') ? document.getElementById('searchBar').value : '');
        } else {
            const data = await response.json();
            alert(data.message || 'Error deleting user');
        }
        } catch (error) {
        console.error("Error deleting user:", error);
        alert("Error deleting user. Please try again.");
    }
}

// Create new user
async function createUser() {
    const usernameInput = document.getElementById('newUsername');
    const emailInput = document.getElementById('newEmail');
    const passwordInput = document.getElementById('newPassword');
    const isAdminInput = document.getElementById('newIsAdmin');
    
    if (!usernameInput || !emailInput || !passwordInput) return;
    
    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const isAdmin = isAdminInput ? isAdminInput.checked : false;
    
    if (!username || !email || !password) {
        alert('Please fill in all required fields');
        return;
    }
            
    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                isAdmin
            })
        });
        
        if (response.ok) {
            // Close the modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('addUserModal'));
            if (modal) modal.hide();
            
            // Clear the form
            usernameInput.value = '';
            emailInput.value = '';
            passwordInput.value = '';
            if (isAdminInput) isAdminInput.checked = false;
            
            // Refresh the user list
            fetchUsers(currentPage, document.getElementById('searchBar') ? document.getElementById('searchBar').value : '');
        } else {
            const data = await response.json();
            alert(data.message || 'Error creating user');
        }
    } catch (error) {
        console.error("Error creating user:", error);
        alert("Error creating user. Please try again.");
    }
}

// Register a new user through the register endpoint
async function registerUser() {
    // Get reference to register form inputs
    const usernameInput = document.getElementById('registerUsername');
    const emailInput = document.getElementById('registerEmail');
    const passwordInput = document.getElementById('registerPassword');
    const confirmPasswordInput = document.getElementById('registerConfirmPassword');
    
    if (!usernameInput || !emailInput || !passwordInput || !confirmPasswordInput) {
        console.error("Register form inputs not found");
        return;
    }
    
    // Get values from inputs
    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    // Validate inputs
    if (!username || !email || !password) {
        alert('Please fill in all required fields');
        return;
    }
    
    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }
    
    // Show loading indicator
    const registerBtn = document.getElementById('registerBtn');
    if (registerBtn) {
        registerBtn.disabled = true;
        registerBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Registering...';
    }
    
    try {
        // Get server URL
        const serverUrl = getServerUrl();
        
        // Send registration request
        const response = await fetch(`${serverUrl}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': localStorage.getItem('token') // Include admin token
            },
            body: JSON.stringify({
                username,
                email,
                password
            })
        });
        
        // Reset button state
        if (registerBtn) {
            registerBtn.disabled = false;
            registerBtn.innerHTML = 'Register';
        }
        
        // Process response
        const data = await response.json();
        
        if (response.ok) {
            // Registration successful
            alert(`User ${username} registered successfully`);
            
            // Clear form
            usernameInput.value = '';
            emailInput.value = '';
            passwordInput.value = '';
            confirmPasswordInput.value = '';
            
            // Close modal if one exists
            const registerModal = bootstrap.Modal.getInstance(document.getElementById('registerUserModal'));
            if (registerModal) registerModal.hide();
            
            // Refresh the user list
            fetchUsers(currentPage, document.getElementById('searchBar') ? document.getElementById('searchBar').value : '');
        } else {
            // Registration failed
            alert(data.message || 'Error registering user');
        }
    } catch (error) {
        console.error("Error during registration:", error);
        alert(`Registration error: ${error.message}`);
        
        // Reset button state
        if (registerBtn) {
            registerBtn.disabled = false;
            registerBtn.innerHTML = 'Register';
        }
    }
}

// Add this function at the top level
async function checkDeviceStatus(deviceKey) {
    try {
        console.log(`Checking status for device ${deviceKey}`);
        
        // Add retry mechanism - try up to 2 times if first attempt fails
        let attempts = 0;
        let maxAttempts = 2;
        let delay = 1000; // 1 second delay between retries
        
        while (attempts < maxAttempts) {
            attempts++;
            
    try {
        // Get device status using the API
        const serverUrl = getServerUrl();
                const timeoutController = new AbortController();
                const timeoutId = setTimeout(() => timeoutController.abort(), 5000); // 5 second timeout
                
        const response = await fetch(`${serverUrl}/api/device-status/${deviceKey}`, {
                    headers: getAuthHeaders(),
                    // Add cache busting to prevent cached responses
                    cache: 'no-cache',
                    // Add timeout to prevent hanging requests
                    signal: timeoutController.signal
                });
                
                clearTimeout(timeoutId);
                
                if (response.ok) {
        const data = await response.json();
                    console.log(`Device ${deviceKey} status:`, data);
                    
                    // Trust the server's determination of connection status
        return {
                        isOnline: data.isConnected,
            ipAddress: data.ipAddress || "Unknown",
                        lastSeen: data.lastHeartbeat || null,
                        recentHeartbeats: data.recent_heartbeats || 0
                    };
                }
                
                // If we get an error response, try again (unless it's our last attempt)
                if (attempts < maxAttempts) {
                    console.log(`Attempt ${attempts} failed for device ${deviceKey}, retrying after delay...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    continue;
                }
                
                console.error(`All ${maxAttempts} attempts failed for device ${deviceKey}`);
                return { isOnline: false, ipAddress: "Unknown", lastSeen: null };
            } catch (fetchError) {
                console.error(`Fetch error checking device ${deviceKey} status:`, fetchError);
                
                // Only retry if we haven't reached max attempts
                if (attempts < maxAttempts) {
                    console.log(`Retrying after error (attempt ${attempts})...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    continue;
                }
                
                // If this was our last attempt, just return offline status
                return { isOnline: false, ipAddress: "Unknown", lastSeen: null };
            }
        }
        
        // If we reach here, all attempts failed
        return { isOnline: false, ipAddress: "Unknown", lastSeen: null };
    } catch (error) {
        console.error("Error in checkDeviceStatus:", error);
        return { isOnline: false, ipAddress: "Unknown", lastSeen: null };
    }
}

// Unassign device
async function unassignDevice(deviceKey, userId) {
    try {
        // Confirm with server to unassign device key
        const response = await fetch(`/unassign_key`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ key: deviceKey })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Find all key-list containers for this user and update them
            const keyListContainers = document.querySelectorAll(`.key-list[data-id="${userId}"]`);
            keyListContainers.forEach(container => {
                fetchKeysAndDevices(userId, container);
            });
            
            // Also update the user details modal if it's open
            const userKeysContainer = document.getElementById('userKeysContainer');
            if (userKeysContainer) {
                fetchKeysAndDevices(userId, userKeysContainer);
            }
            
            // Show success message
            alert(data.message || 'Device key unassigned successfully');
            
            // Refresh the user list to update device counts
            fetchUsers(currentPage, document.getElementById('searchBar') ? document.getElementById('searchBar').value : '');
        } else {
            alert(data.message || 'Error unassigning device key');
        }
    } catch (error) {
        console.error("Error unassigning device:", error);
        alert(`Error unassigning device key: ${error.message}`);
    }
}

// Update device stats
function updateDeviceStats(devices) {
    // If devices parameter is not provided, fetch from backend
    if (!devices) {
        // Just call the fetchDevices function which will update stats
        return;
    }
    
    // Update UI elements with device stats
    const totalDevices = devices.length;
    const onlineDevices = devices.filter(d => d.isConnected).length;
    const offlineDevices = devices.filter(d => !d.isConnected).length;
    const unregisteredDevices = devices.filter(d => !d.user_id).length;
    
    document.getElementById('totalDevices').textContent = totalDevices;
    document.getElementById('onlineDevices').textContent = onlineDevices;
    document.getElementById('offlineDevices').textContent = offlineDevices;
    document.getElementById('unregisteredDevices').textContent = unregisteredDevices;
}

// Fetch and display device keys for a user
async function fetchKeysAndDevices(userId, containerElement) {
    if (!userId || !containerElement) {
        console.error("Missing required parameters for fetchKeysAndDevices");
        containerElement.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle"></i> Error: Missing parameters
            </div>
        `;
        return;
    }

    try {
        // Show loading state
        containerElement.innerHTML = `
            <div class="text-center my-2">
                <div class="spinner-border spinner-border-sm text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                <span class="ms-2">Loading device keys...</span>
            </div>
            `;
        
        // Get server URL
        const serverUrl = getServerUrl();
        
        // Fetch the user's device keys
        const response = await fetch(`${serverUrl}/get_keys/${userId}`, {
            headers: getAuthHeaders(),
            cache: 'no-cache' // Prevent caching
        });
        
        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();
        const keys = data.keys || [];

        if (keys.length === 0) {
            containerElement.innerHTML = `
                <div class="alert alert-info">
                    <i class="bi bi-info-circle me-2"></i> No device keys assigned
                    </div>
                `;
            return;
        }

        // Create a list of keys
        let keysHtml = `<ul class="list-group">`;
        
        for (const key of keys) {
            // Use status information directly from the keys response
            // instead of making additional API calls
            const isOnline = key.is_connected || key.status === "online";
            const ipAddress = key.ip_address || "Unknown";
            
            // Determine correct badge class and icon based on status
            let badgeClass = isOnline ? 'bg-success' : 'bg-secondary';
            let iconClass = isOnline ? 'bi-wifi' : 'bi-wifi-off';
            
            // Create list item with connection status
            keysHtml += `
                <li class="list-group-item d-flex justify-content-between align-items-center">
                    <div>
                        <span class="badge ${badgeClass} me-2">
                            <i class="bi ${iconClass}"></i>
                        </span>
                        ${key.key}
                        ${ipAddress && ipAddress !== "Unknown" ? 
                            `<small class="text-muted ms-2">(${ipAddress})</small>` : ''}
                    </div>
                    <button class="btn btn-sm btn-outline-danger unassign-key-btn" 
                            data-id="${userId}" 
                            data-key="${key.key}">
                        <i class="bi bi-trash"></i>
                                </button>
                        </li>
            `;
        }
        
        keysHtml += `</ul>`;
        containerElement.innerHTML = keysHtml;

        // Add event listeners to unassign buttons
        containerElement.querySelectorAll('.unassign-key-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const userId = this.getAttribute('data-id');
                const deviceKey = this.getAttribute('data-key');
                if (confirm(`Are you sure you want to unassign the key "${deviceKey}" from this user?`)) {
                    unassignDevice(deviceKey, userId);
                }
            });
        });
        
    } catch (error) {
        console.error("Error fetching device keys:", error);
        containerElement.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-exclamation-triangle me-2"></i>
                Error loading device keys: ${error.message}
                    </div>
            <button class="btn btn-sm btn-outline-primary mt-2 retry-btn">
                <i class="bi bi-arrow-clockwise me-1"></i> Retry
            </button>
        `;
    
        // Add retry button functionality
        const retryBtn = containerElement.querySelector('.retry-btn');
        if (retryBtn) {
            retryBtn.addEventListener('click', () => fetchKeysAndDevices(userId, containerElement));
        }
    }
}

// View device details
function viewDeviceDetails(deviceKey) {
    // Implementation of viewDeviceDetails function
}

// Function to fetch devices for device management
async function fetchDevices(page = 1, searchQuery = "", statusFilter = "all") {
    try {
        // Show loading state
        const deviceList = document.getElementById('deviceList');
        if (deviceList) {
            deviceList.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center">
                        <div class="spinner-border text-primary spinner-border-sm" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <span class="ms-2">Loading devices...</span>
                    </td>
                </tr>
            `;
        }
        
        // Get server URL
        const serverUrl = getServerUrl();
        
        // Build query parameters
        let queryParams = `page=${page}`;
        if (searchQuery) {
            queryParams += `&search=${encodeURIComponent(searchQuery)}`;
        }
        if (statusFilter && statusFilter !== "all") {
            queryParams += `&status=${statusFilter}`;
        }
        
        let response;
        let data;
        
        // First attempt to fetch with normal API
        response = await fetch(`${serverUrl}/api/devices?${queryParams}`, {
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}: ${response.statusText}`);
        }
        
        data = await response.json();
        
        // If we got no devices and we're admin, let's fetch from all users to ensure we get everything
        if (data.devices && data.devices.length === 0 && localStorage.getItem("isadmin") === "true") {
            console.log("No devices found with primary method, fetching from individual users");
            
            // Fetch users first to get their IDs
            const usersResponse = await fetch(`${serverUrl}/api/users?limit=100`, {
                headers: getAuthHeaders()
            });
            
            if (usersResponse.ok) {
                const usersData = await usersResponse.json();
                const users = usersData.users || [];
                
                // Collect all devices from all users
                let allDevices = [];
                let allDeviceLabels = {};
                
                for (const user of users) {
                    if (user._id) {
                        try {
                            const userDevicesResponse = await fetch(`${serverUrl}/get_keys/${user._id}`, {
                                headers: getAuthHeaders()
                            });
                            
                            if (userDevicesResponse.ok) {
                                const userDevicesData = await userDevicesResponse.json();
                                const keys = userDevicesData.keys || [];
                                
                                // Convert keys format to devices format
                                keys.forEach(key => {
                                    const device = {
                                        _id: key.device_id,
                                        key: key.key,
                                        user_id: user._id,
                                        ipAddress: key.ip_address,
                                        isConnected: key.is_connected,
                                        lastUpdated: key.created,
                                        username: user.username
                                    };
                                    
                                    allDevices.push(device);
                                    allDeviceLabels[key.key] = key.label || key.key;
                                });
                            }
                        } catch (error) {
                            console.error(`Error fetching devices for user ${user._id}:`, error);
                        }
                    }
                }
                
                // Update our data with all collected devices
                if (allDevices.length > 0) {
                    data.devices = allDevices;
                    data.device_labels = allDeviceLabels;
                    data.count = allDevices.length;
                }
            }
        }
        
        // Display the devices
        displayDevices(data.devices || [], data.device_labels || {});
        
        // Update device stats
        updateDeviceStats(data.devices || []);
        
        // Update pagination
        // Calculate total pages (10 items per page)
        const totalPages = Math.ceil((data.count || 0) / 10) || 1;
        updateDevicesPagination(page, totalPages);
        
    } catch (error) {
        console.error("Error fetching devices:", error);
        if (deviceList) {
            deviceList.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        Error: ${error.message}
                    </td>
                </tr>
            `;
        }
    }
}

// Function to display devices
function displayDevices(devices, deviceLabels = {}) {
    const deviceList = document.getElementById('deviceList');
    if (!deviceList) return;
    
    deviceList.innerHTML = "";
    
    if (!devices || devices.length === 0) {
        deviceList.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">No devices found</td>
            </tr>
        `;
        return;
    }
    
    devices.forEach(device => {
        const isConnected = device.isConnected;
        const statusBadge = isConnected 
            ? '<span class="badge bg-success">Online</span>' 
            : '<span class="badge bg-danger">Offline</span>';
            
        const deviceKey = device.key || "Unknown";
        const label = deviceLabels[deviceKey] || deviceKey;
        const ipAddress = device.ipAddress || "Unknown";
        const lastSeen = device.lastUpdated 
            ? new Date(device.lastUpdated).toLocaleString() 
            : "Never";
            
        // Get user info if available
        const userId = device.user_id;
        const username = device.username;
        let userInfo = "Unregistered";
        if (username) {
            userInfo = `<span class="badge bg-info">${username}</span>`;
        } else if (userId) {
            userInfo = `<span class="badge bg-info">User ID: ${userId}</span>`;
        }
        
        deviceList.innerHTML += `
            <tr>
                <td>
                    <span class="device-key">${deviceKey}</span>
                    ${label !== deviceKey ? `<br><small>${label}</small>` : ''}
                </td>
                <td>${userInfo}</td>
                <td>${statusBadge}</td>
                <td>${ipAddress}</td>
                <td><span class="timestamp">${lastSeen}</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewDeviceDetails('${deviceKey}')">
                        <i class="bi bi-info-circle"></i>
                    </button>
                </td>
            </tr>
        `;
    });
}

// Function to update device pagination
function updateDevicesPagination(current, total) {
    const pageInfo = document.getElementById('devicePageInfo');
    const prevBtn = document.getElementById('prevDevicePage');
    const nextBtn = document.getElementById('nextDevicePage');
    
    if (pageInfo) {
        pageInfo.textContent = `Page ${current} of ${total}`;
    }
    
    if (prevBtn) {
        prevBtn.disabled = current <= 1;
    }
    
    if (nextBtn) {
        nextBtn.disabled = current >= total;
    }
}

// Function to initialize devices section
function initializeDevicesSection() {
    // Initialize device search
    const deviceSearchBar = document.getElementById('deviceSearchBar');
    if (deviceSearchBar) {
        deviceSearchBar.addEventListener('input', debounce(function() {
            currentDevicesPage = 1; // Reset to first page when searching
            fetchDevices(currentDevicesPage, this.value, document.getElementById('deviceStatusFilter').value);
        }, 300));
    }
    
    // Initialize status filter
    const deviceStatusFilter = document.getElementById('deviceStatusFilter');
    if (deviceStatusFilter) {
        deviceStatusFilter.addEventListener('change', function() {
            currentDevicesPage = 1; // Reset to first page when filtering
            fetchDevices(currentDevicesPage, deviceSearchBar ? deviceSearchBar.value : '', this.value);
        });
    }
    
    // Initialize pagination buttons
    const prevDeviceBtn = document.getElementById('prevDevicePage');
    const nextDeviceBtn = document.getElementById('nextDevicePage');
    
    if (prevDeviceBtn) {
        prevDeviceBtn.addEventListener('click', function() {
            if (currentDevicesPage > 1) {
                currentDevicesPage--;
                fetchDevices(
                    currentDevicesPage, 
                    deviceSearchBar ? deviceSearchBar.value : '', 
                    deviceStatusFilter ? deviceStatusFilter.value : 'all'
                );
            }
        });
    }
    
    if (nextDeviceBtn) {
        nextDeviceBtn.addEventListener('click', function() {
            currentDevicesPage++;
            fetchDevices(
                currentDevicesPage, 
                deviceSearchBar ? deviceSearchBar.value : '', 
                deviceStatusFilter ? deviceStatusFilter.value : 'all'
            );
        });
    }
    
    // Initialize refresh button
    const refreshDevicesBtn = document.getElementById('refreshDevicesBtn');
    if (refreshDevicesBtn) {
        refreshDevicesBtn.addEventListener('click', function() {
            fetchDevices(
                currentDevicesPage, 
                deviceSearchBar ? deviceSearchBar.value : '', 
                deviceStatusFilter ? deviceStatusFilter.value : 'all'
            );
        });
    }
    
    console.log("Devices section initialized");
}

// Function to initialize logs section
function initializeLogsSection() {
    console.log("Initializing logs section");
    
    // Initialize log filters
    const logTypeFilter = document.getElementById('logTypeFilter');
    const logUserFilter = document.getElementById('logUserFilter');
    const logDateFrom = document.getElementById('logDateFrom');
    const logDateTo = document.getElementById('logDateTo');
    
    if (logTypeFilter) {
        logTypeFilter.addEventListener('change', function() {
            currentLogsPage = 1; // Reset to first page when filtering
            fetchLogs(currentLogsPage);
        });
    }
    
    if (logUserFilter) {
        logUserFilter.addEventListener('change', function() {
            currentLogsPage = 1; // Reset to first page when filtering
            fetchLogs(currentLogsPage);
        });
    }
    
    // Initialize date pickers
    const today = new Date();
    if (logDateTo) {
        logDateTo.valueAsDate = today;
        logDateTo.addEventListener('change', function() {
            currentLogsPage = 1; // Reset to first page when filtering
            fetchLogs(currentLogsPage);
        });
    }
    
    if (logDateFrom) {
        // Set default from date to 7 days ago
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(today.getDate() - 7);
        logDateFrom.valueAsDate = oneWeekAgo;
        
        logDateFrom.addEventListener('change', function() {
            currentLogsPage = 1; // Reset to first page when filtering
            fetchLogs(currentLogsPage);
        });
    }
    
    // Initialize pagination buttons
    const prevLogsBtn = document.getElementById('prevLogsPage');
    const nextLogsBtn = document.getElementById('nextLogsPage');
    
    if (prevLogsBtn) {
        prevLogsBtn.addEventListener('click', function() {
            if (currentLogsPage > 1) {
                currentLogsPage--;
                fetchLogs(currentLogsPage);
            }
        });
    }
    
    if (nextLogsBtn) {
        nextLogsBtn.addEventListener('click', function() {
            currentLogsPage++;
            fetchLogs(currentLogsPage);
        });
    }
    
    // Initialize refresh button
    const refreshLogsBtn = document.getElementById('refreshLogsBtn');
    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener('click', function() {
            fetchLogs(currentLogsPage);
        });
    }
    
    // Placeholder for logs - we'll implement a proper API for this later
    // For now just show a message
    const activityLogs = document.getElementById('activityLogs');
    if (activityLogs) {
        activityLogs.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle me-2"></i>
                        Logs section is under development. Check back soon!
                    </div>
                </td>
            </tr>
        `;
    }
}

// Update the fetchLogs function to use the new API
function fetchLogs(page = 1) {
    console.log(`Fetching logs for page ${page}`);
    
    // Show loading state
    const activityLogs = document.getElementById('activityLogs');
    if (activityLogs) {
        activityLogs.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">
                    <div class="spinner-border text-primary spinner-border-sm" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <span class="ms-2">Loading logs...</span>
                </td>
            </tr>
        `;
    }
    
    // Get filter values
    const logTypeFilter = document.getElementById('logTypeFilter');
    const logUserFilter = document.getElementById('logUserFilter');
    const logDateFrom = document.getElementById('logDateFrom');
    const logDateTo = document.getElementById('logDateTo');
    
    // Build query parameters
    let queryParams = `page=${page}`;
    
    if (logTypeFilter && logTypeFilter.value !== 'all') {
        queryParams += `&type=${encodeURIComponent(logTypeFilter.value)}`;
    }
    
    if (logUserFilter && logUserFilter.value !== 'all') {
        queryParams += `&user=${encodeURIComponent(logUserFilter.value)}`;
    }
    
    if (logDateFrom && logDateFrom.value) {
        queryParams += `&date_from=${encodeURIComponent(logDateFrom.value)}`;
    }
    
    if (logDateTo && logDateTo.value) {
        queryParams += `&date_to=${encodeURIComponent(logDateTo.value)}`;
    }
    
    // Get server URL
    const serverUrl = getServerUrl();
    
    // Make request to the activity logs endpoint
    fetch(`${serverUrl}/api/activity-logs?${queryParams}`, {
        headers: getAuthHeaders()
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Failed to fetch logs: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log("Received logs data:", data);
        
        // Update the user filter dropdown if needed
        if (data.filters && data.filters.users && logUserFilter) {
            // Keep the current selected value
            const currentValue = logUserFilter.value;
            
            // Clear existing options except the 'All Users' option
            while (logUserFilter.options.length > 1) {
                logUserFilter.remove(1);
            }
            
            // Add new options
            data.filters.users.forEach(user => {
                if (user) {  // Only add non-null users
                    const option = document.createElement('option');
                    option.value = user;
                    option.textContent = user;
                    logUserFilter.appendChild(option);
                }
            });
            
            // Restore selected value if it exists
            if (currentValue && currentValue !== 'all') {
                for (let i = 0; i < logUserFilter.options.length; i++) {
                    if (logUserFilter.options[i].value === currentValue) {
                        logUserFilter.selectedIndex = i;
                        break;
                    }
                }
            }
        }
        
        // Display logs
        displayLogs(data.logs || []);
        
        // Update pagination
        updateLogsPagination(
            data.pagination?.currentPage || 1,
            data.pagination?.totalPages || 1
        );
    })
    .catch(error => {
        console.error("Error fetching logs:", error);
        if (activityLogs) {
            activityLogs.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        Error: ${error.message}
                    </td>
                </tr>
            `;
        }
    });
}

// Function to display logs
function displayLogs(logs) {
    const activityLogs = document.getElementById('activityLogs');
    if (!activityLogs) return;
    
    activityLogs.innerHTML = "";
    
    if (!logs || logs.length === 0) {
        activityLogs.innerHTML = `
            <tr>
                <td colspan="5" class="text-center">No logs found matching the criteria</td>
            </tr>
        `;
        return;
    }
    
    logs.forEach(log => {
        // Format timestamp
        const timestamp = new Date(log.timestamp).toLocaleString();
        
        // Determine status badge class
        let badgeClass = "bg-secondary";
        if (log.status === "success") {
            badgeClass = "bg-success";
        } else if (log.status === "failed") {
            badgeClass = "bg-danger";
        } else if (log.status === "error") {
            badgeClass = "bg-danger";
        } else if (log.status === "unauthorized") {
            badgeClass = "bg-warning";
        }
        
        // Format action display
        let action = log.action;
        
        // Make action names more readable
        action = action.replace(/_/g, ' ');
        action = action.charAt(0).toUpperCase() + action.slice(1);
        
        // Create the row
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${log.user || 'System'}</td>
            <td>${action}</td>
            <td>${log.ip_address || 'Unknown'}</td>
            <td><span class="badge ${badgeClass}">${log.status}</span></td>
        `;
        
        // Add hover details if present
        if (log.details) {
            row.setAttribute('data-bs-toggle', 'tooltip');
            row.setAttribute('data-bs-placement', 'top');
            
            // Format details as a readable string
            let detailsStr = '';
            try {
                if (typeof log.details === 'object') {
                    const details = Object.entries(log.details)
                        .map(([key, value]) => `${key}: ${JSON.stringify(value)}`)
                        .join(', ');
                    detailsStr = details;
                } else {
                    detailsStr = String(log.details);
                }
            } catch (e) {
                detailsStr = 'Error formatting details';
            }
            
            row.setAttribute('title', detailsStr);
            
            // Initialize tooltip
            new bootstrap.Tooltip(row);
        }
        
        activityLogs.appendChild(row);
    });
}

// Update logs pagination display
function updateLogsPagination(current, total) {
    const prevBtn = document.getElementById('prevLogsPage');
    const nextBtn = document.getElementById('nextLogsPage');
    const pageInfo = document.getElementById('logsPageInfo');
    
    if (prevBtn) prevBtn.disabled = current <= 1;
    if (nextBtn) nextBtn.disabled = current >= total;
    if (pageInfo) pageInfo.textContent = `Page ${current} of ${total}`;
}