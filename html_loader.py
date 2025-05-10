import streamlit as st
import os
import base64

def load_static_file(file_path):
    """Load a static file from disk and return its contents"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        return f"Error loading file: {str(e)}"

def render_html(html_content, height=None):
    """Render raw HTML in Streamlit"""
    st.components.v1.html(html_content, height=height, scrolling=True)
    
def display_html_file(file_path, height=600):
    """Load and display an HTML file from the static directory"""
    if os.path.exists(file_path):
        html_content = load_static_file(file_path)
        render_html(html_content, height=height)
        return True
    else:
        st.error(f"File not found: {file_path}")
        return False
        
def get_file_download_link(file_path, link_text="Download file"):
    """Generate a download link for a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = f.read()
        
        b64_data = base64.b64encode(data.encode()).decode()
        file_name = os.path.basename(file_path)
        href = f'<a href="data:text/html;base64,{b64_data}" download="{file_name}">{link_text}</a>'
        return href
    except Exception as e:
        return f"Error creating download link: {str(e)}"
        
def list_static_files(directory="static", extension=None):
    """List all files in the static directory, optionally filtered by extension"""
    try:
        if not os.path.exists(directory):
            return []
            
        files = os.listdir(directory)
        
        if extension:
            files = [f for f in files if f.endswith(extension)]
            
        return files
    except Exception as e:
        st.error(f"Error listing files: {str(e)}")
        return [] 
