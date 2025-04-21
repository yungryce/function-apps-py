#!/usr/bin/env bash

echo "Registering a new user..."
curl POST "http://localhost:7071/api/register" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9",
           "email": "testuser@example.com",
           "first_name": "Test",
           "last_name": "User "
         }'

sleep 3
echo -e "\n"

echo "Logging in with valid credentials..."
curl POST "http://localhost:7071/api/login" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "testP@ssword9"
         }'

sleep 1
echo -e "\n"

echo "Logging in with invalid credentials..."
curl -X POST "http://localhost:7071/api/login" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "testuser",
           "password": "invalidpassword"
         }'

sleep 1
echo -e "\n"

echo "Logging in with non-existent user..."
curl -X POST "http://localhost:7071/api/login" \
     -H "Content-Type: application/json" \
     -d '{
           "username": "nonexistentuser",
           "password": "testP@ssword9"
         }'
echo -e "\n"