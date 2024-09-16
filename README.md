# Task Management API

## Overview

This project is a RESTful API for a task management system built with Node.js, Express, and MongoDB. It provides user authentication and CRUD operations for tasks.

## Setup Instructions

1. Clone the repository:

    git clone https://github.com/yourusername/task-management-api.git <br>
    cd task-management-api

2. Install dependencies:

    npm install

3. Set up environment variables:
    Create a `.env` file in the root directory with the following content:

    PORT=5000<br>
    MONGODB_URI=your_mongodb_connection_string<br>
    JWT_SECRET=your_jwt_secret

    Replace `your_mongodb_connection_string` with your actual MongoDB connection string and generate a strong `JWT_SECRET`.


4. Start the server:

    npm run dev

5. The API will be available at `http://localhost:5000` in development mode, or at `https://yourdomain.com` in production mode. The home page will automatically redirect to the Swagger documentation.

## Approach

1. **Server Setup**: Used Express.js for the web server framework due to its simplicity and wide adoption.

2. **Database**: Chose MongoDB with Mongoose ODM for its flexibility with document-based storage, which suits the varying nature of tasks.

3. **Authentication**: Implemented JWT (JSON Web Tokens) for stateless authentication, allowing scalability and security.

4. **API Structure**: Followed RESTful principles for intuitive and standardized API endpoints.

5. **Validation**: Used express-validator for input validation to ensure data integrity.

6. **Documentation**: Integrated Swagger for clear, interactive API documentation.

7. **Error Handling**: Implemented centralized error handling for consistent error responses.

8. **Dynamic Environment Configuration**: Implemented automatic BASE_URL determination based on the environment, supporting both local development and production deployment without code changes.

## Assumptions

1. **User Model**: Assumed a simple user model with username and password. In a production environment, this would likely be expanded.

2. **Task Model**: Assumed tasks have title, description, due date, and completion status.

3. **Authentication**: Assumed that all task operations require authentication.

4. **Data Persistence**: Assumed that data persistence is required, hence the use of MongoDB.

5. **Scalability**: Assumed the API might need to scale, influencing the choice of stateless authentication and document-based database.

## Assessment Choices for Assessment 1

1. **Node.js and Express**: Chosen for their robust ecosystem, excellent performance for I/O operations, and wide community support.

2. **MongoDB**: Selected for its flexibility with unstructured data and ease of scaling. It allows for easy modification of the task schema if requirements change.

3. **JWT for Authentication**: Chosen for its stateless nature, making it suitable for scalable applications. It also provides a secure method of transmitting information between parties as a JSON object.

4. **Swagger**: Used for its ability to provide interactive API documentation, making it easier for developers to understand and test the API.

5. **Express-validator**: Chosen for its integration with Express.js and its comprehensive validation and sanitization features.

6. **Environment-based URL Configuration**: Chose to dynamically set the BASE_URL based on the environment to seamlessly support both local development and production deployment, enhancing the project's flexibility and ease of use across different stages of development.

These choices were made to create a scalable, maintainable, and well-documented API that adheres to best practices in modern web development.

## Future Improvements

1. Implement refresh tokens for enhanced security
2. Add rate limiting to prevent abuse
3. Set up CI/CD pipelines for automated testing and deployment