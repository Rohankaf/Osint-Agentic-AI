import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def ask_gemini(prompt, model_name="gemini-pro"):
    model = genai.GenerativeModel(model_name)
    response = model.generate_content(prompt)
    return response.text
