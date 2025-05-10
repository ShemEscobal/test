// Initialize device control functions

// Add initialization code to ensure the toggle button works correctly
document.addEventListener("DOMContentLoaded", function() {
    console.log("Initializing LED control button...");
    
    // Set up direct event listener for the toggle button
    const toggleBtn = document.getElementById("toggleBtn");
    if (toggleBtn) {
        console.log("LED control button found, setting up event handler");
        
        // Make sure toggleLedDirect function is globally available
        if (!window.toggleLedDirect) {
            console.error("toggleLedDirect function not defined globally!");
        }
        
        // Make button visually distinct
        toggleBtn.style.cursor = "pointer";
        toggleBtn.style.boxShadow = "0 0 10px rgba(255,0,0,0.5)";
        toggleBtn.classList.add("btn-pulse");
        
        // Set the global window property to ensure the function is accessible
        window.oldToggleLedDirect = window.toggleLedDirect;
        
        // Handle different ways the button might be clicked
        
        // 1. Direct onclick property
        toggleBtn.onclick = function(e) {
            console.log("Toggle button clicked via onclick property");
            // Call the function directly
            if (typeof window.toggleLedDirect === 'function') {
                window.toggleLedDirect();
            } else if (typeof window.oldToggleLedDirect === 'function') {
                window.oldToggleLedDirect();
            } else {
                console.error("No LED toggle function found");
                alert("LED control function not available. Please refresh the page.");
            }
            
            // Prevent default to ensure no conflicts
            if (e) e.preventDefault();
            return false;
        };
        
        // 2. Add a direct event listener as backup approach
        toggleBtn.addEventListener("click", function(e) {
            console.log("Toggle button clicked via event listener");
            e.stopPropagation();
            e.preventDefault();
            
            // Call the function directly
            if (typeof window.toggleLedDirect === 'function') {
                window.toggleLedDirect();
            } else if (typeof window.oldToggleLedDirect === 'function') {
                window.oldToggleLedDirect();
            } else {
                console.error("No LED toggle function found");
                alert("LED control function not available. Please refresh the page.");
            }
            
            return false;
        });
        
        // Force direct invocation method
        const forceClickHandler = function() {
            console.log("Force click handler attached");
            const buttons = document.querySelectorAll('#toggleBtn');
            buttons.forEach(btn => {
                btn.addEventListener('click', function(e) {
                    console.log("Forced click handler triggered");
                    e.stopPropagation();
                    e.preventDefault();
                    if (typeof window.toggleLedDirect === 'function') {
                        window.toggleLedDirect();
                    } else {
                        console.error("toggleLedDirect function not found in forced handler");
                    }
                    return false;
                }, true);
            });
        };
        
        // Run force handler now and after a short delay
        forceClickHandler();
        setTimeout(forceClickHandler, 1000);
        
        // Create a global helper for debugging
        window.debugLedButton = function() {
            console.log("Debug LED button called");
            console.log("Button element:", toggleBtn);
            console.log("onclick property:", toggleBtn.onclick);
            console.log("toggleLedDirect function available:", typeof window.toggleLedDirect === 'function');
            
            // Test direct call
            if (typeof window.toggleLedDirect === 'function') {
                console.log("Directly calling toggleLedDirect");
                window.toggleLedDirect();
            }
        };
        
        // Check initial LED state without showing errors
        checkInitialLedState();
        
        // Set up periodic checks
        setInterval(checkLedStateQuietly, 10000); // Check every 10 seconds
    } else {
        console.warn("LED control button not found in the DOM");
    }
});

// Function to check the initial LED state without showing errors
function checkInitialLedState() {
    // Get the best device IP
    const deviceIP = getBestDeviceIP();
    
    // Try to get current LED state
    fetch(`http://${deviceIP}/led`, { 
        mode: 'cors', 
        method: 'GET', 
        cache: 'no-cache',
        timeout: 2000
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("LED status check failed");
        }
        return response.json();
    })
    .then(data => {
        console.log("Initial LED state:", data.state);
        updateLedButtonLabel(data.state === "on");
        
        // Store successful IP
        localStorage.setItem("lastWorkingDeviceIP", deviceIP);
    })
    .catch(err => {
        console.log("Initial LED check error (normal if device is not connected):", err.message);
    });
}

// Check LED state quietly - doesn't display errors
function checkLedStateQuietly() {
    try {
        // Get the best device IP
        const deviceIP = getBestDeviceIP();
        
        fetch(`http://${deviceIP}/led`, { 
            mode: 'cors', 
            method: 'GET', 
            cache: 'no-cache',
            timeout: 1000
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            throw new Error("LED check failed");
        })
        .then(data => {
            console.log("Current LED state from periodic check:", data.state);
            const isOn = data.state === "on";
            updateLedButtonLabel(isOn);
            
            // Store successful IP
            localStorage.setItem("lastWorkingDeviceIP", deviceIP);
        })
        .catch(err => {
            // Just log the error quietly
            console.log("Periodic LED check error:", err.message);
        });
    } catch (e) {
        console.log("Error in periodic LED check:", e);
    }
}

// Function to update the status display
function updateStatus(message, className = "text-info") {
    const statusDisplay = document.getElementById("statusDisplay");
    if (statusDisplay) {
        statusDisplay.innerHTML = message;
        statusDisplay.className = `alert text-center fs-5 p-3 mb-4 ${className}`;
    }
}

// Function to update just the LED button label
function updateLedButtonLabel(isOn) {
    const toggleBtn = document.getElementById("toggleBtn");
    if (!toggleBtn) return;
    
    console.log(`Updating LED button to show LED is ${isOn ? 'ON' : 'OFF'}`);
    
    // Update button text and icon
    toggleBtn.innerHTML = `<i class="bi bi-lightbulb${isOn ? '-fill' : ''}"></i> LED is ${isOn ? 'ON' : 'OFF'}`;
    
    // Update button style
    toggleBtn.className = isOn ? 
        "btn btn-success w-100 py-3 mb-4" : 
        "btn btn-primary w-100 py-3 mb-4";
}

// Main function for LED control
window.toggleLedDirect = function() {
    console.log("toggleLedDirect function called");
    
    // Get a reference to the status display element
    const statusElement = document.getElementById("statusDisplay");
    if (statusElement) {
        statusElement.innerHTML = "Contacting device, please wait...";
        statusElement.className = "alert alert-info text-center fs-5 p-3 mb-4";
    }
    
    // Get IP from the highlighted row in the table
    let deviceIP = null;
    
    // First try to get the IP from the selected row (blue highlighted row)
    const selectedRow = document.querySelector("tr.table-primary");
    if (selectedRow) {
        const ipCell = selectedRow.querySelector("td:nth-child(4)");
        if (ipCell && ipCell.textContent) {
            deviceIP = ipCell.textContent.trim();
            console.log(`Found IP in selected row: ${deviceIP}`);
        }
    }
    
    // If no IP found in selected row, look for the blue highlighted row in device info
    if (!deviceIP || deviceIP === "Unknown") {
        const deviceIpElement = document.getElementById("deviceIp");
        if (deviceIpElement && deviceIpElement.textContent) {
            deviceIP = deviceIpElement.textContent.trim();
            console.log(`Found IP in device info: ${deviceIP}`);
        }
    }
    
    // If still no IP, try to find one in the table with 192.168.* pattern
    if (!deviceIP || deviceIP === "Unknown" || deviceIP.startsWith("127.0.0.1")) {
        const allIpCells = document.querySelectorAll("td:nth-child(4)");
        for (const cell of allIpCells) {
            const ip = cell.textContent.trim();
            if (ip && ip.startsWith("192.168.")) {
                deviceIP = ip;
                console.log(`Found 192.168.* IP in table: ${deviceIP}`);
                break;
            }
        }
    }
    
    // Last resort - look for IoTPoD2023-NEW-KEY-5670 row specifically
    if (!deviceIP || deviceIP === "Unknown" || deviceIP.startsWith("127.0.0.1")) {
        const iotpodRow = document.querySelector("tr:has(td:contains('IoTPoD2023-NEW-KEY-5670'))");
        if (iotpodRow) {
            const ipCell = iotpodRow.querySelector("td:nth-child(4)");
            if (ipCell && ipCell.textContent) {
                deviceIP = ipCell.textContent.trim();
                console.log(`Found IP in IoTPoD row: ${deviceIP}`);
            }
        }
    }
    
    // Still no valid IP? Final backup - search for any visible 192.168.* text on the page
    if (!deviceIP || deviceIP === "Unknown" || deviceIP.startsWith("127.0.0.1")) {
        // Use a broader search approach
        const allText = document.body.innerText;
        const ipMatch = allText.match(/192\.168\.[0-9]{1,3}\.[0-9]{1,3}/);
        if (ipMatch) {
            deviceIP = ipMatch[0];
            console.log(`Found IP in page text: ${deviceIP}`);
        }
    }
    
    // Final fallback - check if there's any stored IP
    if (!deviceIP || deviceIP === "Unknown" || deviceIP.startsWith("127.0.0.1")) {
        deviceIP = localStorage.getItem("lastWorkingDeviceIP") || "192.168.196.80";
        console.log(`Using fallback IP: ${deviceIP}`);
    }
    
    console.log(`Final device IP to use: ${deviceIP}`);
    
    // Store this IP for future use
    localStorage.setItem("lastWorkingDeviceIP", deviceIP);
    
    // First check if the device is reachable
    fetch(`http://${deviceIP}/ping`, { 
        mode: 'cors', 
        method: 'GET', 
        cache: 'no-cache',
        timeout: 2000
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Device not responding (${response.status})`);
        }
        console.log("Device is reachable");
        
        // Now try to get current LED state
        return fetch(`http://${deviceIP}/led`, { 
            mode: 'cors', 
            method: 'GET', 
            cache: 'no-cache',
            timeout: 3000
        });
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Note: ESP32 hardware has inverted LED logic
        // If the device reports state "on", the LED is actually OFF
        // If the device reports state "off", the LED is actually ON
        const reportedState = data.state === "on";
        const visualState = !reportedState; // Invert for display purposes
        
        console.log(`LED state from device: ${data.state} (reported=${reportedState}, visual=${visualState ? "ON" : "OFF"})`);
        
        // Toggle to opposite state in the API call
        // But the visual state should be the opposite of what we send
        const newApiState = reportedState ? "off" : "on";
        const newVisualState = !reportedState;
        
        console.log(`Toggling LED: Sending API state=${newApiState}, expecting visual state=${newVisualState ? "ON" : "OFF"}`);
        
        // Update the button label before making the request - show expected visual state
        updateLedButtonLabel(newVisualState);
        
        // Toggle the LED
        return fetch(`http://${deviceIP}/led?state=${newApiState}`, { 
            mode: 'cors', 
            method: 'GET', 
            cache: 'no-cache',
            timeout: 3000
        });
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Again, invert the reported state for display purposes
        const reportedState = data.state === "on";
        const visualState = !reportedState;
        
        console.log(`LED response: ${data.state} (appears as ${visualState ? "ON" : "OFF"})`);
        
        // Final update to button label to match actual visual state
        updateLedButtonLabel(visualState);
        
        // Update status display with visual state (what user sees)
        if (statusElement) {
            statusElement.innerHTML = `LED turned ${visualState ? "ON" : "OFF"}`;
            statusElement.className = "alert alert-success text-center fs-5 p-3 mb-4";
        }
    })
    .catch(error => {
        console.error(`LED control error: ${error.message}`);
        
        // Update status display with error
        if (statusElement) {
            statusElement.innerHTML = `Network error: ${error.message}. Check that your device (${deviceIP}) is correctly connected.`;
            statusElement.className = "alert alert-danger text-center fs-5 p-3 mb-4";
        }
        
        // Try a simpler direct approach as fallback
        directLedToggle(deviceIP);
    });
};

// Network test functions have been removed as they're no longer needed in the UI

// Function to get the best device IP from the UI
function getBestDeviceIP() {
    let deviceIP = null;
    
    // First try to get the IP from the selected row
    const selectedRow = document.querySelector("tr.table-primary");
    if (selectedRow) {
        const ipCell = selectedRow.querySelector("td:nth-child(4)");
        if (ipCell && ipCell.textContent) {
            const ip = ipCell.textContent.trim();
            // Only use if it's not a localhost address
            if (ip && ip !== "Unknown" && !ip.startsWith("127.") && ip !== "localhost") {
                deviceIP = ip;
                console.log(`Found valid IP in selected row: ${deviceIP}`);
            } else {
                console.log(`Rejected invalid IP in selected row: ${ip}`);
            }
        }
    }
    
    // If no IP found in selected row, look for the device info
    if (!deviceIP) {
        const deviceIpElement = document.getElementById("deviceIp");
        if (deviceIpElement && deviceIpElement.textContent) {
            const ip = deviceIpElement.textContent.trim();
            // Only use if it's not a localhost address
            if (ip && ip !== "Unknown" && !ip.startsWith("127.") && ip !== "localhost" && 
                ip !== "Not available when offline") {
                deviceIP = ip;
                console.log(`Found valid IP in device info: ${deviceIP}`);
            } else {
                console.log(`Rejected invalid IP in device info: ${ip}`);
            }
        }
    }
    
    // If still no IP, try to find one in any table row with 192.168.* pattern
    if (!deviceIP) {
        const allIpCells = document.querySelectorAll("td:nth-child(4)");
        for (const cell of allIpCells) {
            const ip = cell.textContent.trim();
            if (ip && ip.startsWith("192.168.")) {
                deviceIP = ip;
                console.log(`Found 192.168.* IP in table: ${deviceIP}`);
                break;
            }
        }
    }
    
    // Try looking at the "Connected to:" display as a possible source
    if (!deviceIP) {
        const connectedIpElement = document.getElementById("currentDeviceIP");
        if (connectedIpElement && connectedIpElement.textContent) {
            const ip = connectedIpElement.textContent.trim();
            if (ip && ip !== "Unknown" && ip !== "detecting..." && 
                !ip.startsWith("127.") && ip !== "localhost" && 
                ip !== "Not available when offline") {
                deviceIP = ip;
                console.log(`Found IP in "Connected to" display: ${deviceIP}`);
            }
        }
    }
    
    // Last resort - check for stored IP or use default
    if (!deviceIP) {
        const storedIP = localStorage.getItem("lastWorkingDeviceIP") || "192.168.196.80";
        // Verify stored IP is not a localhost address
        if (storedIP && !storedIP.startsWith("127.") && storedIP !== "localhost") {
            deviceIP = storedIP;
            console.log(`Using stored IP: ${deviceIP}`);
        } else {
            // Fallback to the hardcoded default
            deviceIP = "192.168.196.80";
            console.log(`Using hardcoded default IP: ${deviceIP}`);
        }
    }
    
    // Final validation - if somehow we got a localhost IP, use the default
    if (deviceIP && (deviceIP.startsWith("127.") || deviceIP === "localhost")) {
        console.log(`Final validation caught localhost IP: ${deviceIP}, using default instead`);
        deviceIP = "192.168.196.80";
    }
    
    console.log(`Final device IP selected: ${deviceIP}`);
    return deviceIP;
}

// Simple direct toggle without checking current state first
function directLedToggle(ipAddress) {
    console.log("Trying direct LED toggle as fallback");
    
    // If no ipAddress passed, try to get one
    if (!ipAddress || ipAddress === "Unknown" || ipAddress.startsWith("127.0.0.1")) {
        ipAddress = getBestDeviceIP();
    }
    
    // Get status element
    const statusElement = document.getElementById("statusDisplay");
    
    // Due to ESP32 hardware inverted logic, to turn the LED ON visually, 
    // we need to send state=off to the API
    fetch(`http://${ipAddress}/led?state=off`, { 
        mode: 'cors', 
        method: 'GET', 
        cache: 'no-cache',
        timeout: 3000
    })
    .then(response => {
        if (response.ok) {
            console.log("LED turned ON visually (sending 'off' to API)");
            updateLedButtonLabel(true); // true = visually ON
            if (statusElement) {
                statusElement.innerHTML = "LED turned ON (fallback method)";
                statusElement.className = "alert alert-success text-center fs-5 p-3 mb-4";
            }
            return;
        }
        throw new Error(`Error: ${response.status}`);
    })
    .catch(error => {
        console.error(`Fallback toggle error: ${error.message}`);
        
        // Try an even simpler approach
        if (statusElement) {
            statusElement.innerHTML = "Connection failed. Please check that your device is on the same network.";
            statusElement.className = "alert alert-danger text-center fs-5 p-3 mb-4";
        }
    });
}

// Simple direct LED control function that doesn't depend on any state
window.directLedControl = function(turnOn) {
    const ip = getBestDeviceIP();
    
    // Account for hardware inverted logic
    // If we want to turn the LED visually ON, we need to send "off" to the API
    // If we want to turn the LED visually OFF, we need to send "on" to the API
    const apiState = turnOn ? "off" : "on";
    const visualState = turnOn ? "on" : "off";
    
    const url = `http://${ip}/led?state=${apiState}`;
    
    console.log(`Direct LED control: Sending API state=${apiState} to make LED visually ${visualState}`);
    
    fetch(url, { 
        mode: 'cors', 
        method: 'GET', 
        cache: 'no-cache'
    })
    .then(response => {
        if (response.ok) {
            console.log(`LED successfully set to appear ${visualState}`);
            alert(`LED turned ${visualState.toUpperCase()}`);
        } else {
            console.error(`LED control failed: ${response.status}`);
            alert(`Failed to control LED: ${response.status}`);
        }
    })
    .catch(error => {
        console.error(`LED control error: ${error.message}`);
        alert(`Error: ${error.message}`);
    });
};

// Simple function that can be called from the console to directly test the LED
window.testLed = function(state) {
    const visualState = state === true || state === "on" ? "on" : "off";
    // Account for hardware inverted logic
    const apiState = visualState === "on" ? "off" : "on";
    
    const deviceIP = "192.168.196.80";
    const url = `http://${deviceIP}/led?state=${apiState}`;
    
    console.log(`Test LED: Setting visual state to ${visualState} (API state=${apiState})`);
    console.log(`Request URL: ${url}`);
    
    fetch(url, { 
        mode: 'cors', 
        method: 'GET', 
        cache: 'no-cache',
        timeout: 3000
    })
    .then(response => {
        console.log(`Response status: ${response.status} ${response.statusText}`);
        if (response.ok) {
            return response.json();
        }
        throw new Error(`Error: ${response.status}`);
    })
    .then(data => {
        console.log("Success! Response data:", data);
        // The API returns the state it set, but we need to show the visual state
        const visualResult = data.state === "on" ? "OFF" : "ON";
        alert(`LED successfully turned ${visualResult}`);
        
        // Update button label to match visual state
        updateLedButtonLabel(data.state === "off");
    })
    .catch(error => {
        console.error("Test LED Error:", error);
        alert(`Error: ${error.message}`);
    });
};

// Verify essential functions are defined
console.log("Script loaded and functions defined:");
console.log("- toggleLedDirect:", typeof window.toggleLedDirect === 'function' ? "Available ✓" : "Missing ✗");
console.log("- directLedControl:", typeof window.directLedControl === 'function' ? "Available ✓" : "Missing ✗");

// Network test functions have been removed as they're no longer needed in the UI 