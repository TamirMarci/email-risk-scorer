# Chrome Extension (Prototype)

This Chrome Extension is a prototype UI for the Email Risk Scorer.

## Purpose

- Fast iteration
- Rich UI experimentation
- Backend validation

## Architecture

Gmail DOM → Extension → FastAPI → Scoring Engine

## Running

1. Start backend:
uvicorn app.main:app --reload --port 8000

2. Open chrome://extensions  
3. Enable Developer mode  
4. Load unpacked → chrome-extension/

## Limitations

- DOM-based (fragile)
- Not production-ready
