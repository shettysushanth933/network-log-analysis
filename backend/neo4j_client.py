# neo4j_client.py

from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Neo4j connection configuration
# Use 7687 as the default port, as seen in your logs
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687") 
NEO4J_USER = "neo4j"

# ⬇️ ⬇️ ⬇️ THIS IS THE LINE YOU MUST CHANGE ⬇️ ⬇️ ⬇️
# Replace "password123" with your actual Neo4j database password
NEO4J_PASS = "password123" 
# ⬆️ ⬆️ ⬆️ THIS IS THE LINE YOU MUST CHANGE ⬆️ ⬆️ ⬆️


class Neo4jClient:
    def __init__(self):
        self.driver = None
        self.connect()

    def connect(self):
        """Establish connection to Neo4j database"""
        
        # Ensure credentials are provided
        if not NEO4J_PASS or NEO4J_PASS == "your-real-neo4j-password":
            print(f"❌ Neo4j password not set in neo4j_client.py. Please edit the file.")
            self.driver = None
            return None
            
        try:
            print(f"🔗 Connecting to Neo4j at {NEO4J_URI}...")
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(NEO4J_USER, NEO4J_PASS)
            )
            
            # Test connection
            with self.driver.session() as session:
                result = session.run("RETURN 1")
                result.single()
            
            print("✅ Connected to Neo4j successfully")
            return self.driver
            
        except Exception as e:
            print(f"❌ Failed to connect to Neo4j: {e}")
            print("💡 Please check your NEO4J_URI, NEO4J_USER, and NEO4J_PASS in neo4j_client.py")
            self.driver = None
            return None

    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            print("🔒 Neo4j connection closed")

# Create global instance
neo4j_client = Neo4jClient()
driver = neo4j_client.driver