AI Autocorrect Tool

 The AI Autocorrect Tool is a smart web application that corrects grammar, spelling, and fluency errors using advanced NLP techniques. It supports multilingual input, real-time speech-to-text, user authentication, and a responsive, animated user interface.


 Features

 Grammar and spelling correction using **LanguageTool**  
 Multilingual input support with **auto-detection & translation**  
 Speech-to-text (mic input) functionality  
 Animated, modern UI with **dark/light mode toggle**   
 Download & Copy corrected text with a click  
 Responsive design – works beautifully on mobile and desktop

 Technologies Used

| Layer       | Tools / Libraries                        |
|-------------|-------------------------------------------|
| **Frontend**| HTML, CSS, JavaScript, Toastify, Icons    |
| **Backend** | Python (Flask), LanguageTool, Deep-Translator |
| **Database**| SQLite3 with Flask SQLAlchemy             |
| **Auth**    | Flask-Login                               |
| **Extras**  | LangDetect, SpeechRecognition, JS animations |

TO run 

# Terminal 1 - Backend
cd c:\Users\kinga\Downloads\ai-autocorrect-tool-main\AI-Autocorrect-Tool-main
python backend\app.py

# Terminal 2 - Frontend
cd c:\Users\kinga\Downloads\ai-autocorrect-tool-main\AI-Autocorrect-Tool-main\frontend
python -m http.server 8080
