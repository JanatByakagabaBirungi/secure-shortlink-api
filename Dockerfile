FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Use Waitress for a production-ready WSGI server instead of the Flask dev server
CMD ["waitress-serve", "--port=5000", "app:app"]