# 🔥 AI-Powered Network Log Analysis Platform

This project is an end-to-end, real-time network threat analysis platform. It captures network logs, processes them in real-time, stores them in a graph database to model complex relationships, and uses an AI-powered (Groq) backend to perform advanced threat intelligence analysis.

## 🚀 Tech Stack

  * **Core Services**: Docker, Docker Compose
  * **Streaming**: Apache Kafka, Zookeeper
  * **Database**: Neo4j (Graph Database)
  * **Backend**: FastAPI, Uvicorn
  * **Frontend**: Streamlit, Plotly
  * **AI & Data**: Langchain, Langchain-Groq, Pandas, Numpy

## 🛠️ Getting Started

Follow these steps to get the entire platform up and running.

### 1\. Prerequisites

  * **Docker** and **Docker Compose**: Must be installed and running.
  * **Python 3.9+** and `pip`.
  * **Groq AI API Key**: You must have an API key from [Groq](https://groq.com/).

### 2\. Configuration

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/shettysushanth933/network-log-analysis.git
    cd network-log-analysis
    ```

2.  **Create an Environment File:**
    The project uses a `.env` file in the `backend` directory to manage secret keys. Create a file named `.env` inside the `backend` folder:

    ```bash
    touch backend/.env
    ```

3.  **Add Your Groq API Key:**
    Open the `backend/.env` file and add your Groq API key. This is required for the AI analysis to work.

    ```ini
    # backend/.env
    GROQ_API_KEY="your-secret-groq-api-key-here"
    ```

    **Note on Neo4j:** The Neo4j credentials are set in `docker-compose.yml` (`neo4j/password123`) and are matched in the `neo4j_client.py` file (`NEO4J_PASS = "password123"`).

### 3\. Run the Application

The application requires 3-4 separate terminal processes to run.

1.  **Terminal 1: Start Core Infrastructure (Docker):**
    This command starts Zookeeper, Kafka, and Neo4j in the background.

    ```bash
    docker-compose up -d
    ```

      * Wait about 30-60 seconds for the services to initialize.
      * You can check their status with `docker-compose ps`.

2.  **Terminal 2: Install Dependencies & Run Backend API:**
    This starts the FastAPI server, which also automatically starts the Kafka consumer thread.

    ```bash
    # Install Python packages
    pip install -r backend/requirements.txt

    # Run the FastAPI server
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
    ```

    You should see logs indicating a successful connection to Neo4j and Kafka.

3.  **Terminal 3: Run the Streamlit Frontend:**
    This starts the web dashboard.

    ```bash
    streamlit run backend/app.py
    ```

4.  **Terminal 4: Run the Log Producer:**
    This script will start generating fake data and sending it to Kafka, which will then be consumed by the backend and stored in Neo4j.

    ```bash
    python backend/producer.py
    ```

    You should see logs like "✅ Sent normal log: ..."

### 4\. Accessing the Services

  * **Streamlit Dashboard**:
    Open [**http://localhost:8501**](https://www.google.com/search?q=http://localhost:8501) in your browser.

  * **FastAPI Backend (API Docs)**:
    Open [**http://localhost:8000/docs**](https://www.google.com/search?q=http://localhost:8000/docs) to see and interact with the full REST API.

  * **Neo4j Database Browser**:
    Open [**http://localhost:7474**](https://www.google.com/search?q=http://localhost:7474) in your browser.

      * **Connect URI**: `bolt://localhost:7687` (this is the default)
      * **User**: `neo4j`
      * **Password**: `password123` (from `docker-compose.yml`)