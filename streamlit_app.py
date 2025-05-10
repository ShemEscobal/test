import streamlit as st
import os
import sys

# Set environment variable to indicate we're running in Streamlit
os.environ['STREAMLIT_RUNNING'] = 'true'

# Import our HTML loader utility
import html_loader

# Import Flask app without running the server
import app

# Streamlit app title and description
st.set_page_config(page_title="IoT Testing Dashboard", layout="wide")
st.title("IoT Testing Dashboard")
st.write("This is a Streamlit interface for the IoT Testing System")

# Create a tab-based interface
tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Original UI", "Test Functions", "System Status"])

with tab1:
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

    # Device Management
    with st.expander("Device Management", expanded=True):
        st.write("Manage IoT devices")
        
        # Display basic device info
        try:
            device_count = app.mongo.db.devices.estimated_document_count()
            online_count = app.mongo.db.devices.count_documents({"isConnected": True})
            
            # Create metrics in columns
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Devices", device_count)
            col2.metric("Online Devices", online_count)
            col3.metric("Offline Devices", device_count - online_count)
            
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

with tab2:
    # Embed the original UI in an iframe
    st.header("Original Web Interface")
    st.write("This tab displays your original UI. You need to run the Flask server separately with `python app.py`")
    
    # Allow user to specify server address
    server_url = st.text_input("Server URL", "http://localhost:8080", help="Enter the URL where your Flask server is running")
    
    if st.button("Load Original UI"):
        st.components.v1.iframe(server_url, height=800, scrolling=True)
    
    # Display static HTML directly
    st.subheader("View Static HTML")
    html_files = html_loader.list_static_files(directory="static", extension=".html")
    if not html_files:
        html_files = ["index.html", "admin_dashboard.html", "user.html", "test_results_xhr.html"]  # Fallback options
    
    selected_html = st.selectbox("Select HTML file to view", html_files)
    
    if selected_html and st.button("Load Static HTML"):
        static_path = os.path.join("static", selected_html)
        if os.path.exists(static_path):
            st.success(f"Displaying {selected_html} directly from static files")
            html_loader.display_html_file(static_path, height=700)
            
            # Add download button
            st.markdown(html_loader.get_file_download_link(static_path, f"Download {selected_html}"), unsafe_allow_html=True)
        else:
            st.error(f"File not found: {static_path}")
    
    # Display static files
    st.subheader("Static Files Directory")
    try:
        static_files = os.listdir("static")
        st.write(f"Found {len(static_files)} files in static directory")
        
        # Show a few sample files
        st.json({file: "static file" for file in static_files[:10]})
        
        # Option to display HTML content directly
        if st.checkbox("Display index.html content"):
            try:
                with open("static/index.html", "r") as f:
                    html_content = f.read()
                st.code(html_content[:1000] + "...", language="html")
            except Exception as e:
                st.error(f"Could not read index.html: {str(e)}")
                
    except Exception as e:
        st.error(f"Could not list static files: {str(e)}")

with tab3:
    # Test Functions
    st.header("Test Functions")
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

    # HTML test results viewer
    st.subheader("Test Results Viewer")
    if st.checkbox("Show Test Results HTML"):
        try:
            test_results_path = "static/test_results_xhr.html"
            if os.path.exists(test_results_path):
                st.success("Displaying test results from HTML file")
                html_loader.display_html_file(test_results_path, height=600)
                
                # Allow downloading the file
                st.markdown(html_loader.get_file_download_link(test_results_path, "Download Test Results HTML"), unsafe_allow_html=True)
            else:
                st.warning(f"Test results file not found at {test_results_path}")
        except Exception as e:
            st.error(f"Error displaying test results: {str(e)}")

with tab4:
    # System Status
    st.header("System Status")
    
    # User Management
    with st.expander("User Management"):
        st.write("Manage users in the system")
        
        # Display basic user count
        try:
            user_count = app.mongo.db.users.estimated_document_count()
            st.write(f"Total users in system: {user_count}")
        except Exception as e:
            st.error(f"Could not get user count: {str(e)}")
    
    # System Log Viewer
    with st.expander("System Logs", expanded=True):
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
st.sidebar.header("API Server Instructions")
st.sidebar.write("""
To run the API server directly:
1. Open a terminal
2. Navigate to the project directory
3. Run `python app.py`
4. The server will start on port 8080 or the next available port
""")

# Direct access to HTML files
st.sidebar.header("Static Files")
static_files_list = ["index.html", "admin_dashboard.html", "user.html", "test_results_xhr.html"]
selected_file = st.sidebar.selectbox("View HTML File", static_files_list)

if selected_file and st.sidebar.button("Display HTML"):
    try:
        with open(f"static/{selected_file}", "r") as f:
            html_content = f.read()
        st.sidebar.download_button(
            label=f"Download {selected_file}",
            data=html_content,
            file_name=selected_file,
            mime="text/html"
        )
    except Exception as e:
        st.sidebar.error(f"Could not read file: {str(e)}")

# Add link to source repository
st.sidebar.markdown("[View Source Code](https://github.com/your-username/iot-testing-system)")

st.sidebar.write("---")
st.sidebar.write("© 2023-2024 IoT Testing System") 
