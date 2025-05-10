# DataPod IoT Dashboard

A web-based dashboard for IoT device management and control.

## Features

- Real-time device monitoring
- LED control for connected devices
- User authentication
- Module configuration
- Custom device labels
- Network scanning

## Fixes Applied

The dashboard has been updated to address several issues:

1. **Database Connection Handling**:
   - Improved MongoDB connection detection
   - User-friendly warning banner with retry option
   - Graceful degradation when database is unavailable

2. **Device Display**:
   - Enhanced device discovery that works for all users
   - Multiple fallback methods for finding devices
   - Fixed user ID discovery and storage
   - Improved display of device status

3. **Error Recovery**:
   - Added retry mechanisms for failed connections
   - Better error handling throughout the application
   - Visual indicators for connection state

## How to Run

1. Start the MongoDB server (if available)
2. Run the server starter:
   ```
   node start_server.js
   ```
3. Open a browser and navigate to http://localhost:3000

## Troubleshooting

### Database Connection Issues

If you see a "Database connection issue detected" warning:

1. Check that MongoDB is running
2. Click the "Retry" button to attempt reconnection
3. Devices will still be shown with cached data when possible

### No Devices Showing

If no devices appear in the dashboard:

1. Check that you're logged in (your username should appear in the top right)
2. Verify that your user account has registered devices
3. Try clicking "Scan for devices" in the empty devices table
4. Check network connectivity to any physical IoT devices

## Architecture

The application consists of:

- Frontend (HTML/CSS/JavaScript)
- Backend API (Node.js)
- MongoDB database

The fixes are implemented directly in the main script.js file, avoiding the need for multiple separate fix files.

## For Developers

The consolidated fixes are implemented in a maintainable way:

- `checkMongoDBConnection()` - Enhanced to provide better error handling
- `showMongoDBWarning()` - Creates a user-friendly warning banner
- `retryDatabaseConnection()` - Allows users to attempt reconnection
- `findIoTPod()` - Improved with multiple fallback methods for device discovery
- `processAndDisplayDevices()` - Centralizes device processing logic

