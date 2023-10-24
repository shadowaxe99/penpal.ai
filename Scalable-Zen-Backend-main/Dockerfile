# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install required packages
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available for the app
EXPOSE 8080

# Define the command to run the app using gunicorn
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8080", "--workers=2"]