import os
from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

def get_groq_llm():
    """Initialize and return a Groq LLM client."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable not set.")
    
    llm = ChatGroq(
        api_key=api_key,
        model_name="openai/gpt-oss-120b",
        temperature=0.1,
        max_tokens=2000
    )

    return llm

def test_groq_connection():
    """Test Groq API connection."""
    try:
        llm = get_groq_llm()
        response = llm.invoke("Analyze this trend: cases increased 15% this week. What does this suggest?")
        print(f"Groq API connection successful. Response: {response.content[:100]}...")
        return True
    except Exception as e:
        print(f"Groq API connection failed: {e}")
        return False