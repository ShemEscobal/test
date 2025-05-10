/**
 * Login page fixes and enhancements
 * This script handles login form submit and tests server connectivity
 */

document.addEventListener('DOMContentLoaded', function() {
    // Set up the login form submit handler
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
        console.log('Login form handler attached');
    }
    
    // Set up server URL field with stored value
    const serverUrlField = document.getElementById('serverUrl');
    if (serverUrlField) {
        // Get server URL from localStorage or compute a default
        const savedUrl = localStorage.getItem('serverUrl') || '';
        
        // Default to localhost if empty or contains problematic values
        if (!savedUrl || savedUrl.includes(':3000') || savedUrl.includes('192.168.8.142')) {
            serverUrlField.value = 'localhost';
            localStorage.setItem('serverUrl', 'localhost');
            console.log('Reset to default server URL: localhost');
        } else {
            serverUrlField.value = savedUrl;
            console.log('Loaded server URL from storage:', savedUrl);
        }
        
        // Update help text for server URL field
        const serverUrlHelp = document.querySelector('[for="serverUrl"] + input + .form-text');
        if (serverUrlHelp) {
            serverUrlHelp.innerHTML = 'Enter hostname only (e.g., "localhost" or "127.0.0.1"). <a href="#" onclick="showMongoDBHelpModal();return false;">MongoDB Help</a>';
        }
    }
    
    // Set up test connection button
    const testConnectionBtn = document.getElementById('testConnection');
    if (testConnectionBtn) {
        testConnectionBtn.addEventListener('click', diagnoseServerConnection);
        console.log('Test connection button handler attached');
    }
    
    // Set up MongoDB test button
    const testMongoDBBtn = document.getElementById('testMongoDB');
    if (testMongoDBBtn) {
        testMongoDBBtn.addEventListener('click', function() {
            const serverUrlField = document.getElementById('serverUrl');
            const host = serverUrlField && serverUrlField.value ? serverUrlField.value.trim() : 'localhost';
            testMongoDBConnection(host);
        });
        console.log('MongoDB test button handler attached');
    }
    
    // Set up reset settings button
    const resetSettingsBtn = document.getElementById('resetSettings');
    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', function() {
            if (confirm('Reset settings to use localhost?')) {
                setupLocalhost();
            }
        });
        console.log('Reset settings button handler attached');
    }
    
    // Initialize login status
    const loginStatus = document.getElementById('loginStatus');
    if (loginStatus) {
        // Clear any previous status
        loginStatus.innerHTML = '';
    }
    
    // Check for existing login
    checkExistingLogin();
    
    console.log('Login page initialization complete');
}); 