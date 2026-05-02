# Distributed API Gateway with Intelligent Rate Limiting

## Overview
This project is a Distributed API Gateway built using Spring Boot and Spring Cloud Gateway.  
It controls incoming API traffic using rate limiting to protect backend services from overload and misuse.

The system ensures that only limited and valid requests reach the backend, improving reliability and performance.

---

## Features
- API Gateway for routing requests  
- Rate limiting to control traffic  
- Redis for distributed request tracking  
- Client identification using IP / API key  
- Blocks extra requests after limit  
- Prevents server overload  
- Scalable backend design  

---

## Tech Stack
- Java  
- Spring Boot  
- Spring Cloud Gateway  
- Spring Security  
- Redis  
- Lombok  
- Maven  

---

## System Design

Client → API Gateway → Rate Limiter → Redis → Backend Services

---

## How It Works
1. Client sends request to API Gateway  
2. Gateway identifies client (IP / API key)  
3. Redis stores request count  
4. If limit not reached → request forwarded  
5. If limit exceeded → request blocked  

---

## Example
Limit: 10 requests per minute per user  

---

## API Response

Success:
{
  "status": "success",
  "message": "Request allowed"
}

Error:
{
  "status": "error",
  "message": "Too many requests"
}

---

## Setup Instructions

1. Clone repo
git clone https://github.com/omVish009/distributed-api-gateway-rate-limiter.git

2. Go to project folder
cd distributed-api-gateway-rate-limiter

3. Start Redis
redis-server

4. Run project
mvn spring-boot:run

---

## Use Cases
- API protection  
- Prevent spam requests  
- Traffic control  
- Secure backend services  

---

## Future Improvements
- JWT authentication  
- Role-based rate limits  
- Dashboard for monitoring  
- Docker deployment  
- Kubernetes support  

---

## Author
Om Vishwakarma  
https://github.com/omVish009
