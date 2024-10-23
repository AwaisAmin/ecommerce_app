# Ecommerce Backend

## Overview

This is the backend for an eCommerce application built using Node.js, Express, and TypeScript. It serves as a robust foundation for developing scalable and maintainable eCommerce solutions. The application is designed with modular architecture, ensuring easy integration with front-end frameworks like Next.js.

## Features

- **User Registration**: Create new user accounts with email/password.
- **Email Verification**: Confirm user email addresses during registration.
- **Password Reset**: Allow users to reset their passwords via email.
- **Google Authentication**: Enable users to log in using their Google accounts.
- **OTP Authentication**: Secure logins using One-Time Passwords.
- **Role-Based Access Control (RBAC)**: Define user roles (e.g., admin, customer) to restrict access to certain routes.
- **Rate Limiting**: Prevent abuse by limiting repeated requests to the API.
- **Secure HTTP Headers**: Use middleware to enhance security by setting various HTTP headers.
- **Logging and Monitoring**: Log requests and monitor application performance for better maintenance.

### Future Enhancements

- Additional authentication methods (e.g., social logins, phone number verification).
- Advanced product management features (e.g., inventory management, advanced search).
- Integration with payment gateways for seamless transactions.
- Analytics and reporting features for tracking sales and user engagement.

## Technology Stack

- **Node.js**: JavaScript runtime for building scalable network applications.
- **Express.js**: Fast, unopinionated, minimalist web framework for Node.js.
- **TypeScript**: A superset of JavaScript that compiles to plain JavaScript.
- **MongoDB**: NoSQL database for storing user and product data.
- **Mongoose**: ODM for MongoDB and Node.js.
- **Nodemailer**: Module for sending emails.
- **dotenv**: Module to load environment variables from a `.env` file.
- **helmet**: Middleware to secure Express apps by setting various HTTP headers.
- **morgan**: HTTP request logger middleware for Node.js.
- **compression**: Middleware to compress HTTP responses.
- **express-rate-limit**: Basic rate-limiting middleware for Express.

## Installation

### Prerequisites

- Node.js (v14 or higher)
- MongoDB instance (local or hosted)
- A Google account for Google OAuth

### Clone the Repository

```bash
git clone https://github.com/yourusername/ecommerce_backend.git
cd ecommerce_backend
```
