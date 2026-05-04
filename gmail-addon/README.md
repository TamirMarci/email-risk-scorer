# Gmail Add-on

This is the official Gmail Add-on implementation.

## Architecture

Gmail → Apps Script → FastAPI → Scoring Engine

## Setup

1. Go to https://script.google.com  
2. Create project  
3. Copy Code.gs + appsscript.json  

## Backend

Run backend and expose with ngrok:
ngrok http 8000

Update BACKEND_URL in Code.gs

## Deployment

Deploy → Test deployment → Install → Open Gmail

## Notes

- Uses Gmail APIs
- UI built with CardService
