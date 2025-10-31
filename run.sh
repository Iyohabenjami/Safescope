#!/bin/bash
if [ -z "$VIRTUAL_ENV" ]; then
  echo "Activate your venv first: source venv/bin/activate"
  exit 1
fi
echo "Loading .env..."
python -c "from dotenv import load_dotenv; load_dotenv(); print('ENV OK')"
echo "Starting Flask app on http://0.0.0.0:8000 ..."
python app.py
