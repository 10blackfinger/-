import sys
import os

# Get the absolute path of the current file
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

# Add the backend directory to the path
backend_path = os.path.join(project_root, "backend")
sys.path.insert(0, backend_path)
sys.path.insert(0, project_root)

# Import the FastAPI app
from app.main import app