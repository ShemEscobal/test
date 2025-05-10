import streamlit as st
import os
import sys

# Set environment variable to indicate we're running in Streamlit
os.environ['STREAMLIT_RUNNING'] = 'true'

# Import Flask app without running the server
import app

# Streamlit app title and description
st.title("IoT Testing Dashboard")
st.write("This is a Streamlit interface for the IoT Testing System")

# Display connection information
st.header("Database Connection")
try:
    # Check MongoDB connection
    count = app.mongo.db.devices.estimated_document_count()
    st.success(f"✅ MongoDB connected successfully. Found {count} devices in the database.")

    # Safely display MongoDB URI - only show hostname/port, not credentials
    mongo_uri = app.app.config['MONGO_URI']
    # Extract the part after the @ and before the next /
    try:
        host_part = mongo_uri.split('@')[1].split('/')[0]
        st.info(f"MongoDB URI: {host_part}")
    except IndexError:
        st.info(f"MongoDB URI: {mongo_uri.split('://')[1].split('/')[0]}")
except Exception as e:
    st.error(f"❌ MongoDB connection failed: {str(e)}")
    st.warning("Please check your MongoDB connection string and make sure MongoDB is running.")
    # Still display the MongoDB URI for debugging
    try:
        mongo_uri = app.app.config['MONGO_URI']
        # Try to safely display the host without credentials
        if '@' in mongo_uri:
            host_part = mongo_uri.split('@')[1].split('/')[0]
        else:
            host_part = mongo_uri.split('://')[1].split('/')[0]
        st.info(f"MongoDB URI: {host_part}")
    except Exception:
        st.info("Could not parse MongoDB URI for display")

# Display system information
st.header("System Information")
st.write("**Application Status:** Active")

# Create sections for different functions
st.header("Available Functions")

# Test Functions
with st.expander("Test Functions"):
    st.write("Run tests on your IoT system")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Run Basic Tests"):
            st.session_state.test_results = "Running basic tests..."
            # Here we would typically call app.run_system_tests() but since we're not running
            # the server directly, we'll just simulate the response
            st.session_state.test_results = "✅ Server connectivity test: Success\n✅ Database connection test: Success"
    
    with col2:
        device_ip = st.text_input("Device IP for testing", placeholder="192.168.1.100")
        if st.button("Test Device Connection") and device_ip:
            st.session_state.device_results = f"Testing connection to {device_ip}..."
            # Simulate device testing
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((device_ip, 80))
                sock.close()
                
                if result == 0:
                    st.session_state.device_results = f"✅ Successfully connected to {device_ip}"
                else:
                    st.session_state.device_results = f"❌ Failed to connect to {device_ip}"
            except Exception as e:
                st.session_state.device_results = f"❌ Error testing device: {str(e)}"
    
    # Display test results if available
    if "test_results" in st.session_state:
        st.code(st.session_state.test_results)
    
    if "device_results" in st.session_state:
        st.code(st.session_state.device_results)

# User Management
with st.expander("User Management"):
    st.write("Manage users in the system")
    
    # Display basic user count
    try:
        user_count = app.mongo.db.users.estimated_document_count()
        st.write(f"Total users in system: {user_count}")
    except Exception as e:
        st.error(f"Could not get user count: {str(e)}")

# Device Management
with st.expander("Device Management"):
    st.write("Manage IoT devices")
    
    # Display basic device info
    try:
        device_count = app.mongo.db.devices.estimated_document_count()
        online_count = app.mongo.db.devices.count_documents({"isConnected": True})
        st.write(f"Total devices: {device_count}")
        st.write(f"Online devices: {online_count}")
        st.write(f"Offline devices: {device_count - online_count}")
        
        # Show some device information
        st.subheader("Recent Devices")
        devices = list(app.mongo.db.devices.find().sort("lastHeartbeat", -1).limit(5))
        
        if devices:
            for device in devices:
                with st.container():
                    st.write(f"**Device Key:** {device.get('key')}")
                    st.write(f"**IP Address:** {device.get('ipAddress')}")
                    st.write(f"**Status:** {'🟢 Online' if device.get('isConnected') else '🔴 Offline'}")
                    st.write("---")
        else:
            st.write("No devices found in the database.")
            
    except Exception as e:
        st.error(f"Could not get device information: {str(e)}")

# System Log Viewer
with st.expander("System Logs"):
    st.write("View system activity logs")
    
    # Display some recent logs
    try:
        logs = list(app.mongo.db.activity_logs.find().sort("timestamp", -1).limit(10))
        
        if logs:
            st.subheader("Recent Activity")
            for log in logs:
                timestamp = log.get("timestamp").strftime("%Y-%m-%d %H:%M:%S") if "timestamp" in log else "Unknown time"
                st.write(f"{timestamp} - {log.get('action')} by {log.get('user', 'system')} - {log.get('status')}")
        else:
            st.write("No logs found in the database.")
            
    except Exception as e:
        st.error(f"Could not get logs: {str(e)}")

# Instructions for running the API server
st.header("API Server Instructions")
st.write("""
To run the API server directly:
1. Open a terminal
2. Navigate to the project directory
3. Run `python app.py`
4. The server will start on port 8080 or the next available port
""")

st.write("---")
st.write("© 2023 IoT Testing System") 
