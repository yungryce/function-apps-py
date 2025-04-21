curl -X POST "http://localhost:7071/api/verify_email" \
-H "Content-Type: application/json" \
-d '{
    "email_token": "your-email-token-here"
}'

curl -X GET "http://localhost:7071/api/get_user/{username}" \
-H "Content-Type: application/json"

curl -X GET "http://localhost:7071/api/users" \
-H "Content-Type: application/json"

curl -X POST "http://localhost:7071/api/resend_confirmation_token/unaqueuser" \
-H "Content-Type: application/json"

token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaHhnYngiLCJpYXQiOjE3Mjk1ODcxNzUsImV4cCI6MTcyOTY3MzU3NX0.qd93ig1jtdBNpKVfhIf67gToBp6aQUtm85cNLPK1C3Y

curl -X DELETE "http://localhost:7071/api/delete_user" \
-H "Content-Type: application/json" \
-H "X-Forwarded-For: 192.168.1.1" \
-H "Authorization: Bearer $token"

curl -X POST "http://localhost:7071/api/forgot_password" \
-H "Content-Type: application/json" \
-d '{
    "email": "tetuser@example.com"
}'

curl -X POST "http://localhost:7071/api/change_password" \
-H "Content-Type: application/json" \
-d '{
  "username": "chxgbx",
  "new_password": "newSecurePassword123",
  "email_token": "O%2vOp"
}'
