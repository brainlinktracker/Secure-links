import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main_vercel import app, init_db

# Initialize the database when the module is imported
try:
    init_db()
    print("✅ Database initialized for Vercel deployment")
except Exception as e:
    print(f"Database initialization error: {e}")

# Export the Flask app for Vercel
app = app

