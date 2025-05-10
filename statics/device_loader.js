/**
 * Device Loader Script
 * 
 * This script will attempt to load devices when the page is loaded,
 * using both the SessionManager and traditional methods to ensure
 * devices are always displayed properly.
 */

(function() {
    // Wait for DOM to be ready
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Device Loader activated');
        
        // Wait a moment for other scripts to initialize
        setTimeout(() => {
            console.log('Attempting to load devices...');
            loadDevices();
        }, 1000);
    });
    
    // If page is already loaded, run immediately
    if (document.readyState === 'complete') {
        console.log('Page already loaded, initializing device loader');
        setTimeout(loadDevices, 1000);
    }
    
    // Main function to load devices
    async function loadDevices() {
        console.log('Device loader running');
        
        const statusDisplay = document.getElementById('statusDisplay');
        if (statusDisplay) {
            statusDisplay.textContent = 'Loading devices from session...';
        }
        
        try {
            // First, try using SessionManager if available
            if (window.SessionManager && typeof window.SessionManager.loadUserDevices === 'function') {
                console.log('Using SessionManager to load devices');
                
                const data = await window.SessionManager.loadUserDevices();
                
                if (data && data.devices && data.devices.length > 0) {
                    console.log(`SessionManager loaded ${data.devices.length} devices successfully`);
                    
                    // If processAndDisplayDevices function exists, use it
                    if (typeof processAndDisplayDevices === 'function') {
                        processAndDisplayDevices(data.devices, data.device_labels || {});
                        
                        if (statusDisplay) {
                            statusDisplay.textContent = `Loaded ${data.devices.length} devices successfully`;
                            statusDisplay.className = 'alert alert-success text-center fs-5 p-3 mb-4';
                        }
                        
                        return true;
                    } else {
                        // If we can't find the function, display devices manually
                        console.warn('processAndDisplayDevices function not found, trying manual display');
                        displayDevicesManually(data.devices);
                    }
                } else {
                    console.warn('SessionManager returned no devices, trying direct API approach');
                    
                    // Try our direct approach
                    const directData = await findUserDevices();
                    if (directData && directData.devices && directData.devices.length > 0) {
                        console.log(`Direct API loaded ${directData.devices.length} devices successfully`);
                        
                        if (typeof processAndDisplayDevices === 'function') {
                            processAndDisplayDevices(directData.devices, directData.device_labels || {});
                            
                            if (statusDisplay) {
                                statusDisplay.textContent = `Loaded ${directData.devices.length} devices via direct API`;
                                statusDisplay.className = 'alert alert-success text-center fs-5 p-3 mb-4';
                            }
                            
                            return true;
                        } else {
                            displayDevicesManually(directData.devices);
                        }
                    }
                }
            } else {
                console.warn('SessionManager not available, trying direct API approach');
                
                // Try direct API approach
                const directData = await findUserDevices();
                if (directData && directData.devices && directData.devices.length > 0) {
                    console.log(`Direct API loaded ${directData.devices.length} devices successfully`);
                    
                    if (typeof processAndDisplayDevices === 'function') {
                        processAndDisplayDevices(directData.devices, directData.device_labels || {});
                        
                        if (statusDisplay) {
                            statusDisplay.textContent = `Loaded ${directData.devices.length} devices via direct API`;
                            statusDisplay.className = 'alert alert-success text-center fs-5 p-3 mb-4';
                        }
                        
                        return true;
                    } else {
                        displayDevicesManually(directData.devices);
                    }
                }
            }
            
            // If we reach here, no devices were loaded yet
            // Try the traditional findIoTPod function
            if (typeof findIoTPod === 'function') {
                console.log('Using findIoTPod to load devices');
                await findIoTPod();
                return true;
            } else {
                console.error('All device loading methods failed');
                
                if (statusDisplay) {
                    statusDisplay.textContent = 'Could not load devices - please refresh the page';
                    statusDisplay.className = 'alert alert-danger text-center fs-5 p-3 mb-4';
                }
            }
        } catch (error) {
            console.error('Error loading devices:', error);
            
            if (statusDisplay) {
                statusDisplay.textContent = 'Error loading devices - please refresh';
                statusDisplay.className = 'alert alert-danger text-center fs-5 p-3 mb-4';
            }
        }
    }
    
    // Function to directly fetch user devices without SessionManager
    async function findUserDevices() {
        try {
            // Get authentication information from localStorage
            const token = localStorage.getItem('token');
            const userId = localStorage.getItem('userId');
            const username = localStorage.getItem('username');
            
            if (!token || (!userId && !username)) {
                console.warn('Missing authentication information for direct API call');
                return { devices: [], device_labels: {}, count: 0 };
            }
            
            // Build the API URL with user information
            const serverUrl = localStorage.getItem('serverUrl') || window.location.origin;
            let queryParams = [];
            if (userId) queryParams.push(`user_id=${userId}`);
            if (username) queryParams.push(`username=${username}`);
            
            const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';
            const apiUrl = `${serverUrl}/api/devices${queryString}`;
            
            console.log(`Direct API call to: ${apiUrl}`);
            
            // Make the API request with proper authentication
            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': token.startsWith('Bearer ') ? token : `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                console.log(`Direct API loaded ${data.devices ? data.devices.length : 0} devices`);
                return data;
            } else {
                console.warn(`Direct API call failed: ${response.status}`);
                
                // No longer trying debug endpoint - it's been removed from the backend
                // Instead, provide a better error message and return empty data
                console.error(`API request failed with status: ${response.status}. Please check your authentication.`);
                
                // Display an error message to the user if there's a status display
                const statusDisplay = document.getElementById('statusDisplay');
                if (statusDisplay) {
                    statusDisplay.textContent = `Error loading devices (${response.status}). Please try again later.`;
                    statusDisplay.className = 'alert alert-danger text-center fs-5 p-3 mb-4';
                }
                
                return { devices: [], device_labels: {}, count: 0 };
            }
        } catch (error) {
            console.error('Error in findUserDevices:', error);
            return { devices: [], device_labels: {}, count: 0 };
        }
    }
    
    // Fallback function to display devices manually if processAndDisplayDevices isn't available
    function displayDevicesManually(devices) {
        console.log('Displaying devices manually', devices);
        
        const tableBody = document.getElementById('deviceSummaryBody');
        if (!tableBody) {
            console.error('Device table body not found');
            return;
        }
        
        // Clear existing rows
        tableBody.innerHTML = '';
        
        // Create a row for each device
        devices.forEach(device => {
            const row = document.createElement('tr');
            row.setAttribute('data-device-key', device.key);
            
            // Device key
            const keyCell = document.createElement('td');
            keyCell.textContent = device.key;
            row.appendChild(keyCell);
            
            // Label
            const labelCell = document.createElement('td');
            labelCell.textContent = device.label || device.key;
            row.appendChild(labelCell);
            
            // Status
            const statusCell = document.createElement('td');
            const statusBadge = document.createElement('span');
            statusBadge.className = `badge rounded-pill ${device.isConnected ? 'bg-success' : 'bg-secondary'}`;
            statusBadge.textContent = device.isConnected ? 'Online' : 'Offline';
            statusCell.appendChild(statusBadge);
            row.appendChild(statusCell);
            
            // IP Address
            const ipCell = document.createElement('td');
            ipCell.textContent = device.ipAddress || 'Unknown';
            row.appendChild(ipCell);
            
            // Type
            const typeCell = document.createElement('td');
            typeCell.textContent = device.type || 'IoTPod';
            row.appendChild(typeCell);
            
            // Action
            const actionCell = document.createElement('td');
            const connectBtn = document.createElement('button');
            connectBtn.className = 'btn btn-sm btn-outline-primary connect-btn';
            connectBtn.textContent = 'Connect';
            connectBtn.setAttribute('data-device-key', device.key);
            connectBtn.setAttribute('data-device-ip', device.ipAddress || 'Unknown');
            actionCell.appendChild(connectBtn);
            row.appendChild(actionCell);
            
            // Add the row to the table
            tableBody.appendChild(row);
        });
        
        // Update the status display
        const statusDisplay = document.getElementById('statusDisplay');
        if (statusDisplay) {
            statusDisplay.textContent = `Loaded ${devices.length} devices`;
            statusDisplay.className = 'alert alert-success text-center fs-5 p-3 mb-4';
        }
        
        // Update pagination info
        const paginationTotal = document.getElementById('paginationTotal');
        if (paginationTotal) {
            paginationTotal.textContent = devices.length;
        }
        
        const paginationStart = document.getElementById('paginationStart');
        if (paginationStart) {
            paginationStart.textContent = devices.length > 0 ? '1' : '0';
        }
        
        const paginationEnd = document.getElementById('paginationEnd');
        if (paginationEnd) {
            paginationEnd.textContent = devices.length;
        }
    }
})(); 