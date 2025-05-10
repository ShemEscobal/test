/**
 * MongoDB Connection Test Utility
 * This helps diagnose MongoDB connection issues
 */

// Function to test MongoDB connection through server API
async function testMongoDBConnection(host) {
    const loginStatusElem = document.getElementById('loginStatus');
    
    if (loginStatusElem) {
        loginStatusElem.innerHTML = `
            <div class="alert alert-info">
                <div class="spinner-border spinner-border-sm text-primary me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                Testing MongoDB connection to ${host || 'localhost'}...
            </div>
        `;
    }
    
    try {
        // Get current server URL from input or localStorage
        const serverUrlInput = document.getElementById('serverUrl');
        const serverUrl = serverUrlInput && serverUrlInput.value ? 
            serverUrlInput.value.trim() : 
            (localStorage.getItem('serverUrl') || window.location.origin);
        
        console.log(`Testing MongoDB connection via ${serverUrl} to ${host || 'default'}`);
        
        // Make an API call to test MongoDB connection
        const response = await fetch(`${serverUrl}/api/test-mongodb`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                host: host || 'localhost'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            console.log('MongoDB connection test result:', data);
            
            if (loginStatusElem) {
                if (data.success) {
                    loginStatusElem.innerHTML = `
                        <div class="alert alert-success">
                            <i class="bi bi-check-circle-fill me-2"></i>
                            Successfully connected to MongoDB at ${data.host}:${data.port}
                            <div class="small mt-2">
                                ${data.message || ''}
                            </div>
                        </div>
                    `;
                } else {
                    loginStatusElem.innerHTML = `
                        <div class="alert alert-danger">
                            <i class="bi bi-database-x me-2"></i>
                            Failed to connect to MongoDB at ${data.host}:${data.port}
                            <div class="small mt-2">
                                ${data.error || ''}
                            </div>
                            <div class="mt-3">
                                <button class="btn btn-sm btn-outline-primary" onclick="showMongoDBHelpModal()">
                                    <i class="bi bi-question-circle me-1"></i>Troubleshooting Help
                                </button>
                            </div>
                        </div>
                    `;
                }
            }
            
            return data;
        } else {
            throw new Error(data.message || 'MongoDB connection test failed');
        }
    } catch (error) {
        console.error('Error testing MongoDB connection:', error);
        
        if (loginStatusElem) {
            loginStatusElem.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    Error testing MongoDB connection
                    <div class="small mt-2">
                        ${error.message}
                    </div>
                    <div class="mt-3">
                        <button class="btn btn-sm btn-outline-primary" onclick="showMongoDBHelpModal()">
                            <i class="bi bi-question-circle me-1"></i>Troubleshooting Help
                        </button>
                    </div>
                </div>
            `;
        }
        
        return {
            success: false,
            error: error.message
        };
    }
}

// Show MongoDB help modal
function showMongoDBHelpModal() {
    // Create modal if it doesn't exist
    let modalEl = document.getElementById('mongodbHelpModal');
    
    if (!modalEl) {
        // Create the modal element
        modalEl = document.createElement('div');
        modalEl.id = 'mongodbHelpModal';
        modalEl.className = 'modal fade';
        modalEl.setAttribute('tabindex', '-1');
        modalEl.setAttribute('aria-labelledby', 'mongodbHelpModalLabel');
        modalEl.setAttribute('aria-hidden', 'true');
        
        modalEl.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="mongodbHelpModalLabel">
                            <i class="bi bi-database me-2"></i>Connection Troubleshooting
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-info">
                            <strong><i class="bi bi-info-circle me-2"></i>Server Information</strong>
                            <p class="mb-1">The application has two parts:</p>
                            <ul>
                                <li><strong>Web Server:</strong> Flask on port 3000</li>
                                <li><strong>Database:</strong> MongoDB on port 27017</li>
                            </ul>
                        </div>
                        
                        <h6>Fixing Connection Issues:</h6>
                        <ol>
                            <li>
                                <strong>Use the correct full URL</strong>
                                <p>Enter the complete URL including protocol and port: <code>http://localhost:3000</code></p>
                            </li>
                            <li>
                                <strong>Make sure Flask is running</strong>
                                <p>The Flask server should be running on port 3000. Run <code>python app.py</code> to start it.</p>
                            </li>
                            <li>
                                <strong>MongoDB should be running</strong>
                                <p>MongoDB should be running on port 27017 - check Windows Services for MongoDB service.</p>
                            </li>
                            <li>
                                <strong>Try local loopback IP</strong>
                                <p>If <code>localhost</code> doesn't work, try <code>http://127.0.0.1:3000</code> instead.</p>
                            </li>
                            <li>
                                <strong>Clear browser cache</strong>
                                <p>Try clearing your browser cache or using incognito/private browsing mode.</p>
                            </li>
                        </ol>
                        
                        <h6 class="mt-4">For localhost development:</h6>
                        <p>The simplest way is to use: <code>http://localhost:3000</code> or <code>http://127.0.0.1:3000</code> in the server URL field.</p>
                        
                        <h6 class="mt-4">For network deployment:</h6>
                        <p>If running the server on a different machine, make sure:</p>
                        <ul>
                            <li>Flask is configured to accept remote connections (host='0.0.0.0')</li>
                            <li>Network firewall allows connections to port 3000</li>
                            <li>The correct IP address is entered (e.g., <code>http://192.168.8.142:3000</code>)</li>
                        </ul>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-success" onclick="useLowercaseLocalhost()">
                            <i class="bi bi-lightning-charge me-1"></i>Use localhost
                        </button>
                        <button type="button" class="btn btn-info" onclick="useLoopbackIP()">
                            <i class="bi bi-lightning-charge me-1"></i>Use 127.0.0.1
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modalEl);
    }
    
    // Show the modal
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
}

// Add TestMongoDB button to Advanced Settings
document.addEventListener('DOMContentLoaded', function() {
    const advancedSettings = document.getElementById('advancedSettings');
    if (advancedSettings) {
        // Find the button container
        const btnContainer = advancedSettings.querySelector('.d-flex');
        if (btnContainer) {
            // Create MongoDB test button
            const testMongoBtn = document.createElement('button');
            testMongoBtn.type = 'button';
            testMongoBtn.className = 'btn btn-sm btn-info';
            testMongoBtn.id = 'testMongoDB';
            testMongoBtn.innerHTML = '<i class="bi bi-database-check me-1"></i>Test MongoDB';
            
            // Add button to container
            btnContainer.appendChild(testMongoBtn);
            
            // Add event listener
            testMongoBtn.addEventListener('click', function() {
                const serverUrlInput = document.getElementById('serverUrl');
                const host = serverUrlInput && serverUrlInput.value ? serverUrlInput.value.trim() : 'localhost';
                testMongoDBConnection(host);
            });
            
            console.log('MongoDB test button added');
        }
    }
});

// Add functions to set specific URL patterns
function useLowercaseLocalhost() {
    const serverUrlInput = document.getElementById('serverUrl');
    if (serverUrlInput) {
        serverUrlInput.value = 'http://localhost:3000';
        localStorage.setItem('serverUrl', 'http://localhost:3000');
        
        // Close modal if open
        const modal = bootstrap.Modal.getInstance(document.getElementById('mongodbHelpModal'));
        if (modal) {
            modal.hide();
        }
        
        // Test connection
        testLocalServer();
    }
}

function useLoopbackIP() {
    const serverUrlInput = document.getElementById('serverUrl');
    if (serverUrlInput) {
        serverUrlInput.value = 'http://127.0.0.1:3000';
        localStorage.setItem('serverUrl', 'http://127.0.0.1:3000');
        
        // Close modal if open
        const modal = bootstrap.Modal.getInstance(document.getElementById('mongodbHelpModal'));
        if (modal) {
            modal.hide();
        }
        
        // Test connection
        testLocalServer();
    }
}