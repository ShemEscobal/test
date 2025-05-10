// Remove hardcoded credentials
// let espIP = null; // Store IoTPod IP when found
let espIP = ""; // Will be populated with selected device IP
let networkPrefix = "192.168.4."; // Default network prefix for IoTPod devices
let ledState = false; // Track current LED state
let scanning = false; // Prevent duplicate scans
let verifiedDevices = []; // Store verified device keys
let userDevices = []; // Store all user devices
let filteredDevices = []; // Store filtered devices for pagination
let selectedDeviceKey = null; // Currently selected device key
let selectedDeviceIP = null; // Currently selected device IP
let deviceMap = new Map(); // Map for quick device lookups by key
let deviceLabels = {}; // Store device labels

// Load device labels from localStorage
try {
    const savedLabels = localStorage.getItem("deviceLabels");
    if (savedLabels) {
        deviceLabels = JSON.parse(savedLabels);
        console.log("Loaded device labels from localStorage:", deviceLabels);
    }
} catch (error) {
    console.error("Error loading device labels:", error);
    // Reset labels if there was an error
    deviceLabels = {};
}

// Module related variables
let connectedModules = []; // Store connected modules
let moduleConfigurations = {}; // Store module configurations
let currentModuleType = null; // Track which module is being configured
let workspaceBlocks = []; // Blocks in the workspace for the current module

// Pagination variables
let currentPage = 1;
let itemsPerPage = 10;
let currentFilter = 'all';
let currentSearchTerm = '';

// Batch update variables
let statusUpdateQueue = [];
let isProcessingStatusUpdates = false;
const MAX_CONCURRENT_STATUS_CHECKS = 5;
let lastFullStatusUpdate = 0;
const FULL_STATUS_UPDATE_INTERVAL = 60000; // 1 minute

// Remove the complex connectionStateManager object
const connectionStateManager = {};

// Add a function to update the status display based on connection state
function updateStatusDisplay() {
    // Get connection indicator element
    const connectionIndicator = document.getElementById("connectionIndicator");
    if (connectionIndicator) {
        if (connectionStateManager.current.isConnected) {
            connectionIndicator.classList.add("connected");
            connectionIndicator.classList.remove("disconnected");
        } else {
            connectionIndicator.classList.remove("connected");
            connectionIndicator.classList.add("disconnected");
        }
    }
    
    // Update the status message
    updateStatus(connectionStateManager.getStatusMessage(), 
        connectionStateManager.current.isConnected ? "text-success" : "text-warning");
    
    // Update the LED control button based on stable connection
    updateLEDControls();
}

// Add a function to update LED controls based on stable connection
function updateLEDControls() {
    // Get toggle button
    const toggleBtn = document.getElementById("toggleBtn");
    if (!toggleBtn) return;
    
    // Only enable controls when we have a stable connection
    if (connectionStateManager.isStableConnection()) {
        toggleBtn.disabled = false;
        // Update LED button state
        updateLEDButton();
    } else {
        // Disable button and show offline state
        toggleBtn.disabled = true;
        toggleBtn.innerHTML = connectionStateManager.isTransitioning() ? 
            `<i class="bi bi-hourglass-split"></i> Connecting...` : 
            `<i class="bi bi-lightbulb"></i> Device Offline`;
        
        toggleBtn.className = "btn btn-lg btn-secondary py-3 fs-5";
    }
}

// Function to ensure all runtime dependencies are present
function ensureRuntimeDependencies() {
    console.log("Checking runtime dependencies...");
    
    // Ensure Bootstrap is available
    if (typeof bootstrap === 'undefined') {
        console.warn("Bootstrap is not defined! Attempting to load it manually.");
        
        // Create script element
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js';
        script.integrity = 'sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN';
        script.crossOrigin = 'anonymous';
        
        // Add to document
        document.head.appendChild(script);
        
        // Log
        console.log("Bootstrap bundle script added to document head");
    }
    
    // Ensure jQuery is available
    if (typeof $ === 'undefined') {
        console.warn("jQuery is not defined! Attempting to load it manually.");
        
        // Create script element
        const script = document.createElement('script');
        script.src = 'https://code.jquery.com/jquery-3.6.3.min.js';
        script.integrity = 'sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU=';
        script.crossOrigin = 'anonymous';
        
        // Add to document
        document.head.appendChild(script);
        
        // Log
        console.log("jQuery script added to document head");
    }
    
    // Create global debug function for checking dependencies
    window.checkDependencies = function() {
        console.log("Checking dependencies:");
        console.log("- Bootstrap:", typeof bootstrap !== 'undefined' ? "loaded" : "not loaded");
        console.log("- jQuery:", typeof $ !== 'undefined' ? "loaded" : "not loaded");
        console.log("- fetch API:", typeof fetch !== 'undefined' ? "available" : "not available");
        
        // Return true if all dependencies are loaded
        return (
            typeof bootstrap !== 'undefined' &&
            typeof $ !== 'undefined' &&
            typeof fetch !== 'undefined'
        );
    };
}

// Initialize the application
document.addEventListener("DOMContentLoaded", function() {
    console.log("Login page initialized");
    
    // Set your default server URL first
    if (!localStorage.getItem('serverUrl')) {
        localStorage.setItem('serverUrl', 'http://127.0.0.1:3000');
        console.log("Setting default server URL to http://127.0.0.1:3000");
    }
    
    // Initialize LED control buttons as disabled by default
    updateLedControlButtons(false);
    
    // Check for runtime dependencies to prevent errors
    ensureRuntimeDependencies();
    
    // Initialize Bootstrap components explicitly
    initializeBootstrapComponents();
    
    // Get the current page filename from the URL path
    const currentPath = window.location.pathname;
    const currentPage = currentPath.substring(currentPath.lastIndexOf('/') + 1).toLowerCase();
    
    console.log("Current page detected:", currentPage);
    
    // Initialize username in the navbar
    initializeUsername();
    
    // Check if admin.js was incorrectly loaded on user.html
    if (currentPage === 'user.html' && typeof initializeUsersSection !== 'undefined') {
        console.error("Error: admin.js was loaded on user.html");
        // Reload the page without admin.js
        window.location.reload();
        return;
    }
    
    // Check MongoDB connection in the background to help with debugging
    checkMongoDBConnection().catch(error => {
        console.warn("MongoDB connection check failed:", error);
    });
    
    // Clear error message if showing
    const errorBanner = document.querySelector('.alert.text-danger');
    if (errorBanner && errorBanner.innerText.includes('Error connecting to server')) {
        // Don't remove it right away, wait to see if we can connect
        console.log("Found error banner, will update after device check");
    }
    
    // Apply the appropriate initialization based on the current page
    if (currentPage === 'user.html') {
        // User dashboard-specific initialization
        console.log("Initializing user dashboard features");
        initializeSidebar();
        setupDashboardEventListeners();
        checkLoginStatus();
        
        // IMPORTANT: Force device loading immediately
        console.log("FORCING IMMEDIATE DEVICE LOADING");
        setTimeout(() => {
            const userId = localStorage.getItem("userId");
            if (userId) {
                console.log("Directly calling findIoTPod to ensure devices appear");
                findIoTPod().catch(err => {
                    console.error("Error in findIoTPod direct call:", err);
                    // If all else fails, show sample devices
                    forceSampleDeviceDisplay();
                }).then(() => {
                    // Check if we successfully loaded devices
                    if (userDevices && userDevices.length > 0) {
                        // We have devices, server must be working
                        console.log("Devices loaded successfully, clearing error message");
                        const errorBanner = document.querySelector('.alert.text-danger');
                        if (errorBanner && errorBanner.innerText.includes('Error connecting to server')) {
                            errorBanner.style.display = 'none';
                            // Show success message instead
                            updateStatus("Connected to server. Devices loaded successfully.", "text-success");
                        }
                        // Update server indicator
                        updateServerConnectionIndicator(true);
                    }
                });
            } else {
                console.warn("No userId found for direct device loading");
                // Show sample devices if no userId is found
                forceSampleDeviceDisplay();
            }
        }, 500); // Short delay to ensure other initialization is complete
        
        // Automatically load user devices without requiring scan button
        const userId = localStorage.getItem("userId");
        if (userId) {
            console.log("Auto-loading devices for user:", userId);
            // Show loading indicator
            showLoadingOverlay("Loading your devices...");
            
            // Load devices automatically 
            autoLoadUserDevices(userId)
                .then(() => {
                    console.log("Auto-loading devices complete");
                    hideLoadingOverlay();
                    
                    // Start periodic status updates after devices are loaded
                    startDeviceStatusUpdates();
                    
                    // Check if we successfully loaded devices
                    if (userDevices && userDevices.length > 0) {
                        // We have devices, server must be working
                        console.log("Devices loaded successfully, clearing error message");
                        const errorBanner = document.querySelector('.alert.text-danger');
                        if (errorBanner && errorBanner.innerText.includes('Error connecting to server')) {
                            errorBanner.style.display = 'none';
                            // Show success message instead
                            updateStatus("Connected to server. Devices loaded successfully.", "text-success");
                        }
                        // Update server indicator
                        updateServerConnectionIndicator(true);
                    }
                })
                .catch(error => {
                    console.error("Error auto-loading devices:", error);
                    hideLoadingOverlay();
                    updateStatus("Could not load all devices. Please refresh the page.", "text-warning");
                });
        }
        
        // Add failsafe to check API directly and ensure devices show up 
        setTimeout(() => {
            console.log("Running API check and failsafe device display");
            if (!userDevices || userDevices.length === 0) {
                checkAPIAndShowDevices();
            }
        }, 2000); // Run after 2 seconds to give other methods a chance
        
        // Initialize test-related functionality
        initializeSyncTestButton();
        updateReconnectionTestButton();
    } else if (currentPage === 'login.html') {
        // Login page-specific initialization
        console.log("Initializing login page");
        initializeLoginPage();
    } else if (currentPage === 'register.html') {
        // Register page-specific initialization
        console.log("Initializing register page");
        initializeRegisterPage();
    } else if (currentPage.includes('test_results') || currentPage.includes('test-results')) {
        // Test results page initialization
        console.log("Initializing test results page");
        initializeSyncTestButton();
        
        // Auto-trigger tests if URL has auto parameter
        if (window.location.search.includes('auto=true')) {
            setTimeout(() => {
                console.log("Auto-triggering tests based on URL parameter");
                const syncTestButton = document.getElementById('syncTestButton');
                if (syncTestButton) {
                    syncTestButton.click();
                }
            }, 1000);
        }
    } else if (currentPage === '') {
        // Handle case where pathname might end with '/' (index page)
        const isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
        const isAdmin = localStorage.getItem("isadmin") === "true";
        
        if (isLoggedIn) {
            if (isAdmin) {
                window.location.href = "admin_dashboard.html";
            } else {
                window.location.href = "user.html";
            }
        } else {
            window.location.href = "login.html";
        }
    }
});

// Function to initialize Bootstrap components
function initializeBootstrapComponents() {
    console.log("Initializing Bootstrap components");
    
    // Make sure Bootstrap is available
    if (typeof bootstrap === 'undefined') {
        console.error("Bootstrap is not defined! Attempting to load it manually.");
        // Try to load Bootstrap if it's not available
        const bootstrapScript = document.createElement('script');
        bootstrapScript.src = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js';
        bootstrapScript.onload = function() {
            console.log("Bootstrap loaded manually");
            initializeModals();
        };
        document.head.appendChild(bootstrapScript);
    } else {
        initializeModals();
    }
    
    // Initialize dropdowns with direct click handlers
    const dropdownMenus = document.querySelectorAll('.dropdown-menu');
    dropdownMenus.forEach(menu => {
        const menuItems = menu.querySelectorAll('.dropdown-item');
        menuItems.forEach(item => {
            // Re-add click handlers to ensure they work
            const originalOnClick = item.onclick;
            item.onclick = function(e) {
                e.stopPropagation(); // Prevent event bubbling
                console.log(`Dropdown item clicked: ${item.textContent.trim()}`);
                
                // Call original handler if it exists
                if (typeof originalOnClick === 'function') {
                    return originalOnClick.call(this, e);
                }
            };
        });
    });
}

// Function to initialize modals
function initializeModals() {
    // Pre-initialize all modals on the page
    const modalElements = document.querySelectorAll('.modal');
    console.log(`Found ${modalElements.length} modals to initialize`);
    
    modalElements.forEach(modalElement => {
        try {
            // Create modal instance
            new bootstrap.Modal(modalElement);
            console.log(`Modal initialized: ${modalElement.id || 'unnamed modal'}`);
        } catch (error) {
            console.error(`Error initializing modal ${modalElement.id || 'unnamed modal'}:`, error);
        }
    });
}

// Function to initialize username display in the navbar
function initializeUsername() {
    const loggedInUser = document.getElementById("loggedInUser");
    if (!loggedInUser) return;
    
    // Get username from localStorage
    const username = localStorage.getItem("username");
    
    console.log("Initializing username display with:", username);
    
    // Always display the username if available, regardless of value
    if (username && username.trim() !== "") {
        loggedInUser.textContent = username;
        console.log("Username displayed:", username);
        
        // If username is different from what's shown, refresh display
        if (loggedInUser.textContent !== username) {
            console.log("Username mismatch, updating display");
            // Try setting innerHTML as fallback
            loggedInUser.innerHTML = username;
            
            // Double check by updating after a short delay (in case of any DOM-related issues)
            setTimeout(() => {
                if (loggedInUser && loggedInUser.textContent !== username) {
                    loggedInUser.textContent = '';
                    loggedInUser.textContent = username;
                    console.log("Username refreshed with delay:", username);
                }
            }, 100);
        }
    } else {
        // If no username is found, check if we're logged in
        const isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
        if (!isLoggedIn) {
            // If not logged in, redirect to login page
            window.location.href = "login.html";
        } else {
            // We're logged in but no username? Use a placeholder
            loggedInUser.textContent = "User";
            console.log("No username found but user is logged in, using placeholder");
            
            // Try to fetch user details from userId if available
            const userId = localStorage.getItem("userId");
            if (userId) {
                fetchUserDetails(userId)
                    .then(userData => {
                        if (userData && userData.username) {
                            // Update localStorage and display
                            localStorage.setItem("username", userData.username);
                            loggedInUser.textContent = userData.username;
                            console.log("Updated username from user details:", userData.username);
                        }
                    })
                    .catch(error => {
                        console.error("Error fetching user details:", error);
                    });
            }
        }
    }
}

// Helper function to fetch user details from server
async function fetchUserDetails(userId) {
    try {
        // Get the server URL dynamically from location or fallback
        const serverUrl = localStorage.getItem("serverUrl") || window.location.origin || "http://127.0.0.1:3000";
        
        const response = await fetch(`${serverUrl}/api/user/${userId}`, {
            headers: getAuthHeaders(),
            cache: 'no-cache'
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error("Failed to fetch user details:", error);
        return null;
    }
}

// Initialize sidebar functionality
function initializeSidebar() {
    const sidebarCollapse = document.getElementById('sidebarCollapse');
    const sidebar = document.getElementById('sidebar');
    const content = document.getElementById('content');
    
    if (sidebarCollapse && sidebar && content) {
        // Check if we're on a mobile device and adjust sidebar accordingly
        if (window.innerWidth < 768) {
            sidebar.classList.add('collapsed');
            content.classList.add('expanded');
        }
        
        // Add click event to toggle sidebar
        sidebarCollapse.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            content.classList.toggle('expanded');
        });
        
        // Handle window resize
        window.addEventListener('resize', function() {
            if (window.innerWidth < 768) {
                sidebar.classList.add('collapsed');
                content.classList.add('expanded');
            }
        });
    }
    
    // Add click events for tab navigation
    const tabLinks = document.querySelectorAll('#sidebar ul.components li a');
    if (tabLinks.length > 0) {
        tabLinks.forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Get tab text to determine action
                const tabText = this.textContent.trim();
                
                // Special case for Settings
                if (tabText === 'Settings') {
                    console.log("Sidebar settings link clicked");
                    openSettingsModal();
                    return;
                }
                
                // Regular tab switching behavior
                // Remove active class from all sidebar items
                document.querySelectorAll('#sidebar ul.components li').forEach(item => {
                    item.classList.remove('active');
                });
                
                // Add active class to clicked item
                this.parentElement.classList.add('active');
                
                // Switch to the selected tab
                switchTab(tabText);
            });
        });
    }
}

// Function to switch between tabs
function switchTab(tabName) {
    console.log("Switching to tab:", tabName);
    
    // Get all content sections
    const devicesSection = document.getElementById('deviceSummarySection');
    const analyticsSection = document.getElementById('analyticsSection');
    const deviceInfoCard = document.getElementById('deviceInfoCard');
    const connectionCard = document.querySelector('.card:has(.connection-indicator)');
    const controlPanel = document.querySelector('.card:has(.device-controls)');
    
    // Hide everything first
    if (deviceInfoCard) deviceInfoCard.classList.add('d-none');
    
    // Show appropriate section based on tab
    switch(tabName) {
        case 'Dashboard':
            // Show main dashboard elements
            if (devicesSection) devicesSection.style.display = 'block';
            if (connectionCard) connectionCard.style.display = 'block';
            if (controlPanel) controlPanel.style.display = 'block';
            if (analyticsSection) analyticsSection.style.display = 'none';
            if (selectedDeviceKey && deviceInfoCard) deviceInfoCard.classList.remove('d-none');
            break;
            
        case 'Analytics':
            // Show analytics elements (placeholder)
            if (devicesSection) devicesSection.style.display = 'none';
            if (connectionCard) connectionCard.style.display = 'none';
            if (controlPanel) controlPanel.style.display = 'none';
            if (deviceInfoCard) deviceInfoCard.classList.add('d-none');
            if (analyticsSection) analyticsSection.style.display = 'block';
            break;
            
        case 'Settings':
            // Open settings modal
            openSettingsModal();
            // But keep dashboard view
            switchTab('Dashboard');
            break;
            
        default:
            // Default to dashboard
            if (devicesSection) devicesSection.style.display = 'block';
            if (connectionCard) connectionCard.style.display = 'block';
            if (controlPanel) controlPanel.style.display = 'block';
            if (analyticsSection) analyticsSection.style.display = 'none';
            if (selectedDeviceKey && deviceInfoCard) deviceInfoCard.classList.remove('d-none');
            break;
    }
}

// Setup event listeners for the dashboard
function setupDashboardEventListeners() {
    console.log("Setting up dashboard event listeners");
    
    // Add event listener to the logout button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.replaceWith(logoutBtn.cloneNode(true)); // Clone to remove any existing handlers
        const newLogoutBtn = document.getElementById("logoutBtn");
        
        // Directly assign the logoutUser function instead of using an anonymous function
        newLogoutBtn.addEventListener("click", function(e) {
            console.log("Logout button clicked");
            e.preventDefault();
            logoutUser();
        });
        
        // Also add it as an onclick attribute for redundancy
        newLogoutBtn.onclick = function(e) {
            e.preventDefault();
            console.log("Logout button onclick triggered");
            logoutUser();
            return false;
        };
    } else {
        console.error("Logout button not found!");
    }
    
    // Add direct click handler for the settings button - using jQuery for better compatibility
    if (typeof $ !== 'undefined') {
        $('#settingsBtn').off('click').on('click', function(e) {
            e.preventDefault();
            console.log("Settings button clicked (jQuery)");
            $('#settingsModal').modal('show');
            return false;
        });
        console.log("Settings button handler attached using jQuery");
    } else {
        // Fallback to regular JavaScript
        const settingsBtn = document.getElementById("settingsBtn");
        if (settingsBtn) {
            settingsBtn.replaceWith(settingsBtn.cloneNode(true)); // Clone to remove any existing handlers
            const newSettingsBtn = document.getElementById("settingsBtn");
            
            newSettingsBtn.addEventListener("click", function(e) {
                console.log("Settings button clicked");
                e.preventDefault();
                e.stopPropagation(); // Prevent event from propagating to parent elements
                
                // Close the dropdown manually
                const dropdownMenu = document.querySelector('.dropdown-menu');
                if (dropdownMenu && dropdownMenu.classList.contains('show')) {
                    dropdownMenu.classList.remove('show');
                }
                
                // Call our settings function directly
                openSettingsModal();
            });
        } else {
            console.error("Settings button not found!");
        }
    }
    
    // Add event listener for the save settings button
    const saveSettingsBtn = document.getElementById("saveSettingsBtn");
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener("click", function() {
            console.log("Saving settings");
            
            // Get the network prefix value
            const networkPrefix = document.getElementById("networkPrefix").value;
            
            // Save to localStorage for persistence
            if (networkPrefix) {
                localStorage.setItem("networkPrefix", networkPrefix);
            }
            
            // Get any other settings that need to be saved
            
            // Close the modal
            if (typeof $ !== 'undefined') {
                $('#settingsModal').modal('hide');
            } else {
                const settingsModal = bootstrap.Modal.getInstance(document.getElementById("settingsModal"));
                if (settingsModal) {
                    settingsModal.hide();
                }
            }
            
            // Show confirmation
            updateStatus("Settings saved successfully", "text-success");
        });
    }
    
    // Rest of the event listeners...
    // Initialize device controls, pagination controls, etc.
    initializeDeviceControls();
    initializePaginationControls();
    initializeSearchAndFilter();
}

// Function to test the IoT device connectivity and endpoints
// ... existing code ...

// Function to check MongoDB connection
async function checkMongoDBConnection(silent = false) {
    try {
        console.log("Checking MongoDB connection...");
        const serverUrl = localStorage.getItem("serverUrl") || window.location.origin || "http://127.0.0.1:3000";
        
        // Use SessionManager for authenticated requests if available
        const fetchWithAuth = window.SessionManager && window.SessionManager.fetchWithAuth || 
                             ((url, options) => fetch(url, { 
                                 ...options, 
                                 headers: getAuthHeaders(),
                                 cache: 'no-cache'
                             }));
        
        // Try to get MongoDB status
        const response = await fetchWithAuth(`${serverUrl}/api/debug/mongo-status`);
        
        // Process response
        if (response.ok) {
            const data = await response.json();
            if (data.status === "connected") {
                console.log("MongoDB is connected:", data.message);
                
                // Check if there was a previous MongoDB warning and hide it
                const warningBanner = document.getElementById("mongoDbWarning");
                if (warningBanner) {
                    warningBanner.style.display = "none";
                }
                
                return true;
            } else {
                console.warn("MongoDB status check returned error:", data.message);
                
                if (!silent) {
                    showMongoDBWarning();
                }
                
                return false;
            }
        } else {
            console.warn("Failed to check MongoDB status:", response.status);
            
            if (!silent) {
                showMongoDBWarning();
            }
            
            return false;
        }
    } catch (error) {
        console.error("Error checking MongoDB connection:", error);
        
        if (!silent) {
            showMongoDBWarning();
        }
        
        return false;
    }
}

// Function to show MongoDB warning
function showMongoDBWarning() {
    console.log("Showing MongoDB warning...");
    
    // Check if warning already exists
    let warningBanner = document.getElementById("mongoDbWarning");
    
    if (!warningBanner) {
        // Create the warning banner
        warningBanner = document.createElement("div");
        warningBanner.id = "mongoDbWarning";
        warningBanner.className = "alert alert-warning text-center mb-4";
        warningBanner.innerHTML = `
            <strong><i class="bi bi-exclamation-triangle-fill me-2"></i>Database Connection Issue</strong>
            <p class="mb-1">There was a problem connecting to the database. Some features may not work properly.</p>
            <button class="btn btn-sm btn-outline-dark mt-2" onclick="retryDatabaseConnection()">
                <i class="bi bi-arrow-clockwise me-1"></i> Retry Connection
            </button>
        `;
        
        // Find appropriate place to insert warning
        const contentArea = document.querySelector(".container-fluid.p-4");
        if (contentArea) {
            // Insert at the beginning of content area
            contentArea.insertBefore(warningBanner, contentArea.firstChild);
        } else {
            // Fallback - append to body
            document.body.appendChild(warningBanner);
        }
    } else {
        // Show the existing warning
        warningBanner.style.display = "block";
    }
}

// Function to retry database connection
async function retryDatabaseConnection() {
    console.log("Retrying database connection...");
    
    // Show loading indicator in the warning banner
    const warningBanner = document.querySelector("#mongoDbWarning");
    if (warningBanner) {
        warningBanner.innerHTML = `
            <strong><i class="bi bi-arrow-repeat me-2 spin"></i>Reconnecting...</strong>
            <p class="mb-1">Attempting to reconnect to the database...</p>
        `;
    }
    
    // Retry the connection check
    const connected = await checkMongoDBConnection();
    
    if (connected) {
        console.log("Reconnection successful!");
        
        // Hide the warning banner
        if (warningBanner) {
            warningBanner.style.display = "none";
        }
        
        // Refresh device data
        findIoTPod();
        
        return true;
    } else {
        console.log("Reconnection failed");
        
        // Show failure message
        if (warningBanner) {
            warningBanner.innerHTML = `
                <strong><i class="bi bi-exclamation-triangle-fill me-2"></i>Database Connection Failed</strong>
                <p class="mb-1">Could not connect to the database. Some features may not work properly.</p>
                <button class="btn btn-sm btn-outline-dark mt-2" onclick="retryDatabaseConnection()">
                    <i class="bi bi-arrow-clockwise me-1"></i> Try Again
                </button>
            `;
        }
        
        return false;
    }
}

// Expose the retry function globally for the warning banner button
window.retryDatabaseConnection = retryDatabaseConnection;

// Enhanced function to find IoT devices with better error handling and retry
async function findIoTPod() {
    console.log("Searching for IoT devices...");
    
    // Show loading indicator
    showLoadingOverlay("Loading your devices...");
    
    // FIRST TRY THE DEBUG ENDPOINT FOR TEST DEVICES
    try {
        const serverUrl = localStorage.getItem("serverUrl") || window.location.origin || "http://127.0.0.1:3000";
        const userId = localStorage.getItem("userId") || "";
        
        console.log("Trying the debug test devices endpoint first");
        const debugUrl = `${serverUrl}/api/debug/get-test-devices${userId ? '?user_id=' + userId : ''}`;
        console.log("Debug URL:", debugUrl);
        
        const response = await fetch(debugUrl);
        if (response.ok) {
            const data = await response.json();
            console.log("Debug test devices response:", data);
            
            // Process devices if any were returned
            if (data.devices && data.devices.length > 0) {
                console.log(`Found ${data.devices.length} test devices`);
                
                // Update the user ID in localStorage if provided and not already set
                if (data.user_id && !localStorage.getItem("userId")) {
                    console.log(`Saving userId to localStorage: ${data.user_id}`);
                    localStorage.setItem("userId", data.user_id);
                }
                
                // Process devices
                processAndDisplayDevices(data.devices, data.device_labels || {});
                hideLoadingOverlay();
                return data.devices[0];
            }
        } else {
            console.warn("Debug test devices endpoint failed:", response.status);
        }
    } catch (debugError) {
        console.error("Error using debug test devices endpoint:", debugError);
    }
    
    // CONTINUE WITH NORMAL APPROACH IF DEBUG ENDPOINT FAILED
    try {
        // Debug: Let's check what's in localStorage first
        console.log("LocalStorage contents (relevant keys):");
        console.log("- userId:", localStorage.getItem("userId"));
        console.log("- username:", localStorage.getItem("username"));
        console.log("- token:", localStorage.getItem("token") ? "Present" : "Missing");
        
        // First check MongoDB connection
        const mongoConnected = await checkMongoDBConnection(true);
        if (!mongoConnected) {
            console.warn("MongoDB connection issue detected before loading devices");
        }
        
        // Get devices from server only - no demo devices
        try {
            console.log("Getting devices from server");
            const username = localStorage.getItem("username") || "";
            const userId = localStorage.getItem("userId") || "";
            const serverUrl = localStorage.getItem("serverUrl") || window.location.origin || "http://127.0.0.1:3000";
            
            // FALLBACK: If no real devices are found, use a placeholder
            let realDevicesFound = false;
            
            // Check token manually - helpful for debugging
            const token = localStorage.getItem("token");
            console.log("Token from localStorage:", token ? "Present (length: " + token.length + ")" : "Missing");
            
            // Use SessionManager for authenticated requests if available
            const fetchWithAuth = window.SessionManager && window.SessionManager.fetchWithAuth || 
                                 ((url, options) => fetch(url, { 
                                     ...options, 
                                     headers: getAuthHeaders(),
                                     cache: 'no-cache'
                                 }));
            
            // Check session and auth status before making device requests
            console.log("Checking current session status first...");
            try {
                const sessionResponse = await fetch(`${serverUrl}/check-session`, {
                    headers: getAuthHeaders(),
                    credentials: 'include'
                });
                
                if (sessionResponse.ok) {
                    const sessionData = await sessionResponse.json();
                    console.log("Session check response:", sessionData);
                    
                    // If we got valid session info, use it for subsequent requests
                    if (sessionData.userId && !userId) {
                        console.log(`Got userId from session: ${sessionData.userId}`);
                        localStorage.setItem("userId", sessionData.userId);
                    }
                } else {
                    console.warn("Session check failed:", sessionResponse.status);
                }
            } catch (sessionError) {
                console.error("Error checking session:", sessionError);
            }

            // Try the debug endpoint first to diagnose issues
            console.log("Calling debug endpoint to diagnose device issues...");
            try {
                const debugResponse = await fetchWithAuth(`${serverUrl}/api/debug/user-devices`);
                if (debugResponse.ok) {
                    const debugData = await debugResponse.json();
                    console.log("Debug endpoint response:", debugData);
                    
                    // If debug endpoint returned devices, use them!
                    if (debugData.devices && debugData.devices.length > 0) {
                        console.log(`Debug endpoint returned ${debugData.devices.length} devices, using those`);
                        const devices = debugData.devices.map(d => {
                            return {
                                key: d.key,
                                ipAddress: d.ipAddress,
                                isConnected: d.isConnected,
                                _id: d.id
                            };
                        });
                        
                        processAndDisplayDevices(devices, {});
                        hideLoadingOverlay();
                        realDevicesFound = true;
                        return devices[0];
                    }
                    
                    // Also update userId if we discovered it through debug
                    if (debugData.session_user_id && !userId) {
                        console.log(`Setting userId from debug info: ${debugData.session_user_id}`);
                        localStorage.setItem("userId", debugData.session_user_id);
                    }
                } else {
                    console.warn("Debug endpoint failed:", debugResponse.status);
                }
            } catch (debugError) {
                console.error("Error calling debug endpoint:", debugError);
            }
            
            // Re-fetch userId in case it was updated
            const updatedUserId = localStorage.getItem("userId");
            
            // Priority 1: Try with user ID if available (most reliable)
            if (updatedUserId) {
                console.log(`Using userId: ${updatedUserId}`);
                
                // Log headers for debugging
                const authHeaders = getAuthHeaders();
                console.log("Auth headers:", Object.keys(authHeaders));
                console.log("Authorization header format:", 
                            authHeaders.Authorization ? 
                            (authHeaders.Authorization.startsWith("Bearer") ? "Bearer format" : "Token only") : 
                            "No Authorization header");
                
                const deviceResponse = await fetchWithAuth(`${serverUrl}/api/devices?user_id=${updatedUserId}`);
                
                if (deviceResponse.ok) {
                    const data = await deviceResponse.json();
                    console.log(`Found ${data.devices ? data.devices.length : 0} devices using userId parameter`);
                    
                    if (data.devices && data.devices.length > 0) {
                        // Process devices
                        processAndDisplayDevices(data.devices, data.device_labels);
                        hideLoadingOverlay();
                        realDevicesFound = true;
                        return data.devices[0];
                    } else {
                        console.warn("API returned success but no devices");
                    }
                } else {
                    console.warn("Failed to get devices using userId:", deviceResponse.status);
                    
                    // Try to get error details
                    try {
                        const errorData = await deviceResponse.json();
                        console.warn("Error response:", errorData);
                    } catch (e) {
                        // Ignore parsing errors
                    }
                }
            }
            
            // Priority 2: Try username if available
            if (username) {
                console.log(`Using username: ${username}`);
                const deviceResponse = await fetchWithAuth(`${serverUrl}/api/devices?username=${username}`);
                
                if (deviceResponse.ok) {
                    const data = await deviceResponse.json();
                    console.log(`Found ${data.devices ? data.devices.length : 0} devices using username parameter`);
                    
                    if (data.devices && data.devices.length > 0) {
                        // Process devices
                        processAndDisplayDevices(data.devices, data.device_labels);
                        hideLoadingOverlay();
                        realDevicesFound = true;
                        return data.devices[0];
                    }
                } else {
                    console.warn("Failed to get devices using username:", deviceResponse.status);
                }
            }
            
            // Priority 3: Try admin access as fallback
            console.log("Trying admin access as fallback");
            const deviceResponse = await fetchWithAuth(`${serverUrl}/api/devices`);
            
            if (deviceResponse.ok) {
                const data = await deviceResponse.json();
                console.log(`Found ${data.devices ? data.devices.length : 0} devices as admin`);
                
                if (data.devices && data.devices.length > 0) {
                    // Process devices
                    processAndDisplayDevices(data.devices, data.device_labels);
                    hideLoadingOverlay();
                    realDevicesFound = true;
                    return data.devices[0];
                }
            } else {
                console.warn("Failed to get devices as admin:", deviceResponse.status);
            }
            
            // If we've reached here with no devices found, show a helpful message
            if (!realDevicesFound) {
                console.log("No real devices found, showing empty state");
                
                // Show message explaining no devices were found
                const statusDisplay = document.getElementById("statusDisplay");
                if (statusDisplay) {
                    statusDisplay.innerHTML = `<i class="bi bi-info-circle-fill"></i> No devices found. Please check your account or add a device.`;
                    statusDisplay.className = "alert alert-info text-center";
                }
                
                // Clear the device table to ensure no test devices are shown
                updateDeviceSummaryTable();
                hideLoadingOverlay();
                return null;
            }
        } catch (error) {
            console.error("Error fetching device list:", error);
            showError("Error fetching device list: " + error.message);
        }
    } catch (error) {
        console.error("Error in findIoTPod:", error);
        showError("Error finding IoT devices: " + error.message);
    } finally {
        hideLoadingOverlay();
    }
}

// Helper function to process and display devices
function processAndDisplayDevices(devices, labels) {
    // Set initial status to undefined (which will show as "Connecting...")
    devices.forEach(device => {
        device.isConnected = undefined; // Use undefined to indicate "checking" state
        device.connectingSince = new Date();
    });
    
    // Update global variables
    userDevices = devices;
    filteredDevices = [...userDevices];
    
    // Update device map
    deviceMap.clear();
    userDevices.forEach(device => {
        deviceMap.set(device.key, device);
    });
    
    // Update device labels if provided
    if (labels) {
        for (const [key, label] of Object.entries(labels)) {
            deviceLabels[key] = label;
        }
        localStorage.setItem("deviceLabels", JSON.stringify(deviceLabels));
    }
    
    // Update the device table to show connecting status
    updateDeviceSummaryTable();
    updateStatus(`Found ${devices.length} device(s), checking status...`, "text-info");
    
    // Start periodic status updates to keep device status current
    startDeviceStatusUpdates();
}

// Function to update the device summary table with current device data
function updateDeviceSummaryTable() {
    console.log("Updating device summary table");
    
    // Get the table body element
    const tableBody = document.getElementById("deviceSummaryBody");
    if (!tableBody) {
        console.error("Device table body not found!");
        return;
    }
    
    // Clear the table body
    tableBody.innerHTML = "";
    
    // If no devices, show a message
    if (!filteredDevices || filteredDevices.length === 0) {
        console.warn("No devices to display");
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-3">
                    <i class="bi bi-info-circle me-2"></i> No devices found for your account
                </td>
            </tr>
        `;
        
        // Update pagination info
        updatePaginationInfo(0);
        return;
    }
    
    // Create rows for devices
    filteredDevices.forEach(device => {
        // Skip if device has no key
        if (!device.key) {
            console.warn("Device missing key:", device);
            return;
        }
        
        // Create row
        const row = document.createElement("tr");
        row.setAttribute("data-device-key", device.key);
        
        // Device key
        const keyCell = document.createElement("td");
        keyCell.textContent = device.key;
        row.appendChild(keyCell);
        
        // Label - use label from device, fallback to deviceLabels object, then key
        const labelCell = document.createElement("td");
        labelCell.textContent = device.label || deviceLabels[device.key] || device.key;
        row.appendChild(labelCell);
        
        // Status
        const statusCell = document.createElement("td");
        const statusBadge = document.createElement("span");
        
        if (device.isConnected === true) {
            statusBadge.className = "badge rounded-pill bg-success";
            statusBadge.textContent = "Online";
        } else if (device.isConnected === false) {
            statusBadge.className = "badge rounded-pill bg-secondary";
            statusBadge.textContent = "Offline";
        } else {
            statusBadge.className = "badge rounded-pill bg-info";
            statusBadge.textContent = "Connecting...";
        }
        
        statusCell.appendChild(statusBadge);
        row.appendChild(statusCell);
        
        // IP Address
        const ipCell = document.createElement("td");
        ipCell.textContent = device.ipAddress || "Unknown";
        row.appendChild(ipCell);
        
        // Type
        const typeCell = document.createElement("td");
        typeCell.textContent = device.type || "IoTPod";
        row.appendChild(typeCell);
        
        // Action
        const actionCell = document.createElement("td");
        const connectBtn = document.createElement("button");
        connectBtn.className = "btn btn-sm btn-outline-primary connect-btn";
        connectBtn.textContent = "Connect";
        connectBtn.onclick = function() {
            // Get IP address from device or use fallback mechanism
            const deviceIP = device.ipAddress || getBestDeviceIP();
            
            // Connect to device (helper function)
            connectToDevice(device.key, deviceIP);
            
            // Update device info displays
            updateDeviceInfoDisplay(device.key, deviceIP);
            
            // Highlight this row
            const allRows = tableBody.querySelectorAll('tr');
            allRows.forEach(r => r.classList.remove('table-primary'));
            row.classList.add('table-primary');
        };
        
        actionCell.appendChild(connectBtn);
        row.appendChild(actionCell);
        
        // Add the row to the table
        tableBody.appendChild(row);
    });
    
    // Update pagination info (if pagination controls exist)
    updatePaginationInfo(filteredDevices.length);
}

// Helper function to update pagination information
function updatePaginationInfo(total) {
    const paginationStart = document.getElementById("paginationStart");
    const paginationEnd = document.getElementById("paginationEnd");
    const paginationTotal = document.getElementById("paginationTotal");
    
    if (paginationStart) paginationStart.textContent = total > 0 ? "1" : "0";
    if (paginationEnd) paginationEnd.textContent = total.toString();
    if (paginationTotal) paginationTotal.textContent = total.toString();
}

// Function to start periodic device status updates
function startDeviceStatusUpdates() {
    console.log("Starting device status updates");
    
    // Clear any existing interval
    if (window.deviceStatusInterval) {
        clearInterval(window.deviceStatusInterval);
    }
    
    // Immediately check device status
    checkAllDeviceStatus();
    
    // Then set up interval to check periodically (every 10 seconds)
    window.deviceStatusInterval = setInterval(checkAllDeviceStatus, 10000);
}

// Function to check status of all devices
async function checkAllDeviceStatus() {
    if (!userDevices || userDevices.length === 0) return;
    
    console.log(`Checking status for ${userDevices.length} devices`);
    const serverUrl = localStorage.getItem("serverUrl") || window.location.origin || "http://127.0.0.1:3000";
    const authHeaders = getAuthHeaders();
    
    // Check status for each device
    for (const device of userDevices) {
        if (!device.key) continue;
        
        try {
            // Call the API to get current device status
            const response = await fetch(`${serverUrl}/api/device-status/${device.key}`, {
                headers: authHeaders,
                cache: 'no-cache'
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Update device status in the map
                const deviceInMap = deviceMap.get(device.key);
                if (deviceInMap) {
                    deviceInMap.isConnected = data.is_connected;
                    deviceInMap.ipAddress = data.ip_address;
                    deviceInMap.lastSeen = data.last_seen;
                }
                
                // Update device in the original array
                const deviceIndex = userDevices.findIndex(d => d.key === device.key);
                if (deviceIndex !== -1) {
                    userDevices[deviceIndex].isConnected = data.is_connected;
                    userDevices[deviceIndex].ipAddress = data.ip_address;
                    userDevices[deviceIndex].lastSeen = data.last_seen;
                }
            } else {
                console.warn(`Error getting status for device ${device.key}: ${response.status}`);
                // Mark device as offline if we can't get status
                const deviceInMap = deviceMap.get(device.key);
                if (deviceInMap) {
                    deviceInMap.isConnected = false;
                }
                
                const deviceIndex = userDevices.findIndex(d => d.key === device.key);
                if (deviceIndex !== -1) {
                    userDevices[deviceIndex].isConnected = false;
                }
            }
        } catch (error) {
            console.error(`Error checking status for device ${device.key}:`, error);
            // Mark device as offline on error
            const deviceInMap = deviceMap.get(device.key);
            if (deviceInMap) {
                deviceInMap.isConnected = false;
            }
            
            const deviceIndex = userDevices.findIndex(d => d.key === device.key);
            if (deviceIndex !== -1) {
                userDevices[deviceIndex].isConnected = false;
            }
        }
    }
    
    // Update the device table to reflect new status
    updateDeviceSummaryTable();
    
    // Also update the selected device info if one is selected
    if (selectedDeviceKey) {
        updateDeviceInfoDisplay(selectedDeviceKey, selectedDeviceIP);
    }
    
    console.log("Device status check complete");
}

// Expose findIoTPod function globally
window.findIoTPod = findIoTPod;

// Function to connect to a specific device
async function connectToDevice(deviceKey, deviceIP) {
    console.log(`Connecting to device ${deviceKey} at IP ${deviceIP}`);
    
    // Show loading indicator
    showLoadingOverlay(`Connecting to ${deviceKey}...`);
    
    try {
        // Save selected device info
        selectedDeviceKey = deviceKey;
        selectedDeviceIP = deviceIP;
        
        // Store device key and IP in localStorage
        localStorage.setItem("deviceKey", deviceKey);
        localStorage.setItem("espIP", deviceIP);
        
        // Get device from map to check its known status
        const device = deviceMap.get(deviceKey);
        let isConnected = false;
        
        // If we have a valid IP that's not "Unknown" or "Offline", consider it connected
        if (deviceIP && deviceIP !== "Unknown" && deviceIP !== "Offline") {
            console.log(`Device ${deviceKey} has IP ${deviceIP} - considering it online`);
            isConnected = true;
            
            // Also check device record's isConnected status if available
            if (device) {
                // If device has a known status in our data, use that
                if (device.isConnected === true) {
                    console.log(`Device ${deviceKey} is already known to be online`);
                    isConnected = true;
                }
                
                // Update device status in the map
                device.isConnected = isConnected;
                
                // Update the device table to reflect current status
                updateDeviceSummaryTable();
            }
        }
        
        // Try to get device status as an additional verification
        // But don't override isConnected if we already know it's true
        if (!isConnected) {
            try {
                const statusResponse = await fetch(`http://${deviceIP}/status`, {
                    mode: 'cors',
                    method: 'GET',
                    cache: 'no-cache',
                    timeout: 3000
                });
                
                if (statusResponse.ok) {
                    const statusData = await statusResponse.json();
                    console.log("Device status:", statusData);
                    
                    // Update device status in the map and table
                    if (device) {
                        device.isConnected = true;
                        device.lastStatus = statusData;
                        isConnected = true;
                        
                        // Update the device table
                        updateDeviceSummaryTable();
                    } else {
                        // Even if we don't have the device in our map, we know it responded
                        isConnected = true;
                    }
                }
            } catch (statusError) {
                console.warn("Could not get device status:", statusError);
                // Don't change isConnected if we already determined it's true
                if (!isConnected) {
                    isConnected = false;
                }
            }
        }
        
        // Show appropriate status message
        if (isConnected) {
            updateStatus(`Connected to ${deviceKey}`, "text-success");
        } else {
            updateStatus(`Connection to ${deviceKey} may be limited`, "text-warning");
        }
        
        // Show device info section
        const deviceInfoCard = document.getElementById('deviceInfoCard');
        if (deviceInfoCard) {
            deviceInfoCard.classList.remove('d-none');
        }
        
        // Update device info display
        updateDeviceInfoDisplay(deviceKey, deviceIP, isConnected);
        
        // Update the LED control buttons based on connection status
        updateLedControlButtons(isConnected);
        
        hideLoadingOverlay();
        return true;
    } catch (error) {
        console.error(`Error connecting to device ${deviceKey}:`, error);
        updateStatus(`Failed to connect to ${deviceKey}: ${error.message}`, "text-danger");
        
        // Disable LED control buttons
        updateLedControlButtons(false);
        
        hideLoadingOverlay();
        return false;
    }
}

// Function to update the device info display
function updateDeviceInfoDisplay(deviceKey, deviceIP, isConnected) {
    console.log(`Updating device info display for ${deviceKey}`);
    
    // Get device info elements
    const deviceKeyElem = document.getElementById('deviceKeyDisplay');
    const deviceIPElem = document.getElementById('deviceIPDisplay');
    const deviceNameElem = document.getElementById('deviceNameDisplay');
    const deviceStatusElem = document.getElementById('deviceStatusDisplay');
    
    // Get device from map
    const device = deviceMap.get(deviceKey);
    
    if (deviceKeyElem) deviceKeyElem.textContent = deviceKey;
    if (deviceIPElem) deviceIPElem.textContent = deviceIP;
    
    if (deviceNameElem) {
        // Use label from deviceLabels or key as fallback
        deviceNameElem.textContent = deviceLabels[deviceKey] || deviceKey;
    }
    
    if (deviceStatusElem && device) {
        let statusText = 'Offline';
        let statusClass = 'text-secondary';
        let iconClass = 'x-circle';
        
        if (isConnected) {
            statusText = 'Online';
            statusClass = 'text-success';
            iconClass = 'check-circle-fill';
        } else if (device.isConnected === undefined) {
            statusText = 'Connecting...';
            statusClass = 'text-info';
            iconClass = 'arrow-repeat';
        }
        
        deviceStatusElem.innerHTML = `<span class="${statusClass}">
            <i class="bi bi-${iconClass}"></i> ${statusText}
        </span>`;
    }
    
    // Update the device IP info in the control panel
    const deviceIPInfo = document.getElementById('deviceConnectionStatusText');
    if (deviceIPInfo) {
        if (deviceIP && deviceIP !== "Unknown") {
            deviceIPInfo.innerHTML = `Connected to: <strong>${deviceIP}</strong>`;
        } else {
            deviceIPInfo.textContent = "No connection available";
        }
    }
    
    // Update LED control buttons based on connection status
    updateLedControlButtons(isConnected);
}

// Function to enable/disable LED control buttons based on device connection status
function updateLedControlButtons(isConnected) {
    const ledOnButton = document.getElementById('ledOnButton');
    const ledOffButton = document.getElementById('ledOffButton');
    
    if (ledOnButton && ledOffButton) {
        if (isConnected) {
            console.log("Enabling LED control buttons - device is connected");
            // ledOnButton.disabled = false;  // Removed - always keep buttons enabled
            // ledOffButton.disabled = false; // Removed - always keep buttons enabled
            
            // Update button styles to show they're enabled
            ledOnButton.classList.remove('btn-outline-success');
            ledOnButton.classList.add('btn-success');
            
            ledOffButton.classList.remove('btn-outline-secondary');
            ledOffButton.classList.add('btn-secondary');
        } else {
            console.log("Styling LED control buttons for offline state - but keeping them enabled");
            // ledOnButton.disabled = true;  // Removed - always keep buttons enabled
            // ledOffButton.disabled = true; // Removed - always keep buttons enabled
            
            // Update button styles to show offline state but keep them clickable
            ledOnButton.classList.remove('btn-success');
            ledOnButton.classList.add('btn-outline-success');
            
            ledOffButton.classList.remove('btn-secondary');
            ledOffButton.classList.add('btn-outline-secondary');
        }
    } else {
        console.warn("LED control buttons not found in the DOM");
    }
}

// Function to initialize device controls
function initializeDeviceControls() {
    console.log("Initializing device controls");
    
    // Get scan button
    const scanButton = document.getElementById("scanButton");
    if (scanButton) {
        scanButton.addEventListener("click", function() {
            console.log("Scan button clicked");
            
            // Check if scan is already in progress
            if (scanning) {
                console.log("Scan already in progress, ignoring duplicate request");
                return;
            }
            
            // Set scanning flag
            scanning = true;
            
            // Update button state
            scanButton.disabled = true;
            scanButton.innerHTML = `
                <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                Scanning...
            `;
            
            // Call scan function
            findIoTPod()
                .then(() => {
                    console.log("Scan complete");
                    // Reset button state
                    scanButton.disabled = false;
                    scanButton.innerHTML = `<i class="bi bi-search"></i> Scan for Devices`;
                    scanning = false;
                })
                .catch(error => {
                    console.error("Scan error:", error);
                    // Reset button state
                    scanButton.disabled = false;
                    scanButton.innerHTML = `<i class="bi bi-search"></i> Scan for Devices`;
                    scanning = false;
                    
                    // Show error
                    updateStatus(`Scan failed: ${error.message}`, "text-danger");
                });
        });
    }
    
    // Initialize click events for device rows (for selection)
    document.addEventListener("click", function(e) {
        // The row click functionality has been removed to avoid redundancy with the Connect button
        // Now only the Connect button will trigger device connection
    });
}

// Function to initialize pagination controls
function initializePaginationControls() {
    console.log("Initializing pagination controls");
    
    // Get pagination elements
    const prevButton = document.getElementById("prevPageBtn");
    const nextButton = document.getElementById("nextPageBtn");
    const itemsPerPageSelect = document.getElementById("itemsPerPage");
    
    // Add event listeners for pagination buttons
    if (prevButton) {
        prevButton.addEventListener("click", function() {
            console.log("Previous page button clicked");
            
            if (currentPage > 1) {
                currentPage--;
                updateDeviceSummaryTable();
            }
        });
    }
    
    if (nextButton) {
        nextButton.addEventListener("click", function() {
            console.log("Next page button clicked");
            
            const maxPage = Math.ceil(filteredDevices.length / itemsPerPage);
            
            if (currentPage < maxPage) {
                currentPage++;
                updateDeviceSummaryTable();
            }
        });
    }
    
    // Add event listener for items per page select
    if (itemsPerPageSelect) {
        itemsPerPageSelect.addEventListener("change", function() {
            console.log(`Items per page changed to: ${this.value}`);
            
            itemsPerPage = parseInt(this.value);
            currentPage = 1; // Reset to first page
            
            updateDeviceSummaryTable();
        });
        
        // Set initial value
        itemsPerPageSelect.value = itemsPerPage.toString();
    }
}

// Function to initialize search and filter controls
function initializeSearchAndFilter() {
    console.log("Initializing search and filter controls");
    
    // Get search and filter elements
    const searchInput = document.getElementById("deviceSearchInput");
    const searchButton = document.getElementById("deviceSearchBtn");
    const filterItems = document.querySelectorAll('.dropdown-item[data-filter]');
    
    // Add event listener for search input
    if (searchInput) {
        searchInput.addEventListener("input", function() {
            console.log(`Search input changed: ${this.value}`);
            
            currentSearchTerm = this.value.toLowerCase();
            currentPage = 1; // Reset to first page
            
            // Apply filter and search
            applyFilterAndSearch();
        });
    } else {
        console.warn("Search input not found (deviceSearchInput)");
    }
    
    // Add event listener for search button
    if (searchButton) {
        searchButton.addEventListener("click", function() {
            console.log("Search button clicked");
            
            const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
            currentSearchTerm = searchTerm;
            currentPage = 1; // Reset to first page
            
            // Apply filter and search
            applyFilterAndSearch();
        });
    }
    
    // Add event listeners for filter dropdown items
    if (filterItems.length > 0) {
        filterItems.forEach(item => {
            item.addEventListener("click", function(e) {
                e.preventDefault();
                
                const filter = this.getAttribute('data-filter');
                console.log(`Filter changed to: ${filter}`);
                
                // Update filter dropdown button text
                const filterDropdown = document.getElementById('deviceFilterDropdown');
                if (filterDropdown) {
                    filterDropdown.innerText = `Filter: ${filter.charAt(0).toUpperCase() + filter.slice(1)}`;
                }
                
                currentFilter = filter;
                currentPage = 1; // Reset to first page
                
                // Apply filter and search
                applyFilterAndSearch();
            });
        });
    } else {
        console.warn("Filter items not found");
    }
}

// Function to apply current filter and search criteria
function applyFilterAndSearch() {
    console.log(`Applying filter: ${currentFilter}, search: ${currentSearchTerm}`);
    
    // Filter devices based on criteria
    filteredDevices = userDevices.filter(device => {
        // Apply status filter
        if (currentFilter === 'online' && !device.isConnected) {
            return false;
        }
        
        if (currentFilter === 'offline' && device.isConnected) {
            return false;
        }
        
        // Apply search term
        if (currentSearchTerm) {
            // Get label for search
            const label = deviceLabels[device.key] || device.key;
            
            // Check if search term is in key, label, IP, or type
            return (
                device.key.toLowerCase().includes(currentSearchTerm) ||
                label.toLowerCase().includes(currentSearchTerm) ||
                (device.ipAddress && device.ipAddress.toLowerCase().includes(currentSearchTerm)) ||
                (device.type && device.type.toLowerCase().includes(currentSearchTerm))
            );
        }
        
        return true;
    });
    
    // Update the table
    updateDeviceSummaryTable();
}

// Function to handle empty device state
function forceSampleDeviceDisplay() {
    console.log("No devices found - displaying empty state");
    
    // Clear all device data
    userDevices = [];
    filteredDevices = [];
    deviceMap.clear();
    
    // Update the table to show empty state
    updateDeviceSummaryTable();
    
    // Update status message
    updateStatus("No devices found. Please register a real device to continue.", "text-warning");
    
    return [];
}

// Function to display a loading overlay
function showLoadingOverlay(message = "Loading...") {
    // Check if overlay already exists
    let overlay = document.getElementById("loadingOverlay");
    
    if (!overlay) {
        // Create overlay if it doesn't exist
        overlay = document.createElement("div");
        overlay.id = "loadingOverlay";
        overlay.className = "loading-overlay";
        
        overlay.innerHTML = `
            <div class="loading-spinner-container">
                <div class="spinner-border text-light" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <div class="loading-message text-light mt-3">${message}</div>
            </div>
        `;
        
        document.body.appendChild(overlay);
    } else {
        // Update message if overlay exists
        const messageElem = overlay.querySelector(".loading-message");
        if (messageElem) {
            messageElem.textContent = message;
        }
        
        // Make sure it's visible
        overlay.style.display = "flex";
    }
}

// Function to hide the loading overlay
function hideLoadingOverlay() {
    const overlay = document.getElementById("loadingOverlay");
    if (overlay) {
        overlay.style.display = "none";
    }
}

// Add the getAuthHeaders function directly here since it was in admin.js
function getAuthHeaders() {
    // Use SessionManager if available, otherwise fall back to local implementation
    if (window.SessionManager && typeof window.SessionManager.getAuthHeaders === 'function') {
        return window.SessionManager.getAuthHeaders();
    }

    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');
    
    // Create simplified headers without Bearer token
    const headers = {
        'Content-Type': 'application/json'
    };
    
    // Add username as a custom header instead of Authorization
    if (username) {
        headers['X-Username'] = username;
    }
    
    // Keep token for backward compatibility but don't use Bearer format
    if (token) {
        headers['Authorization'] = token;
    }
    
    return headers;
}

// Add function to update server connection indicator
function updateServerConnectionIndicator() {
    // Get indicator elements
    const serverIndicator = document.getElementById('serverConnectionIndicator');
    const statusDisplay = document.getElementById('statusDisplay');
    
    if (!serverIndicator) return;
    
    // Check if we have devices and at least one device is online
    const hasOnlineDevices = userDevices && userDevices.some(device => device.isConnected === true);
    const hasDevices = userDevices && userDevices.length > 0;
    
    // If we have devices loaded, the server connection must be working
    if (hasDevices) {
        // Update server connection indicator to connected
        serverIndicator.classList.remove('disconnected');
        serverIndicator.classList.add('connected');
        
        // Update status message
        if (statusDisplay && statusDisplay.innerText.includes('Error connecting to server')) {
            if (hasOnlineDevices) {
                updateStatus("Connected to server. Found online devices.", "text-success");
            } else {
                updateStatus("Connected to server. All devices are offline.", "text-info");
            }
        }
    } else {
        // No devices loaded, might be a server issue
        serverIndicator.classList.remove('connected');
        serverIndicator.classList.add('disconnected');
    }
}

// Add a function to load devices using SessionManager
async function loadDevicesWithSessionManager() {
    console.log("Loading devices using SessionManager...");
    
    // Show loading overlay
    showLoadingOverlay("Loading your devices using session manager...");
    
    try {
        // Check if SessionManager exists and has the loadUserDevices method
        if (!window.SessionManager || typeof window.SessionManager.loadUserDevices !== 'function') {
            console.warn("SessionManager or loadUserDevices method not available");
            hideLoadingOverlay();
            return false;
        }
        
        // Call the loadUserDevices method
        const data = await window.SessionManager.loadUserDevices();
        
        if (data.devices && data.devices.length > 0) {
            console.log(`SessionManager loaded ${data.devices.length} devices successfully`);
            
            // Process and display the devices
            processAndDisplayDevices(data.devices, data.device_labels || {});
            
            // Update status message
            updateStatus(`Loaded ${data.devices.length} devices`, "text-success");
            
            // Hide loading overlay
            hideLoadingOverlay();
            return true;
        } else {
            console.warn("SessionManager loaded 0 devices");
            hideLoadingOverlay();
            return false;
        }
    } catch (error) {
        console.error("Error loading devices with SessionManager:", error);
        hideLoadingOverlay();
        return false;
    }
}