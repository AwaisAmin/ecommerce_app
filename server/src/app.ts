// src/app.ts
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import helmet from 'helmet';
import compression from 'compression';
import logger from './middlewares/logger.middleware';
// import authRoutes from './routes/auth.route';

// Load environment variables
dotenv.config();

const app = express();

// Port
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Logging
app.use(morgan('combined')); // Use morgan for logging HTTP requests
// app.use(logger); // Custom logger middleware

// Security
app.use(helmet()); // Secure your app with HTTP headers
app.use(compression());

// Routes
// app.use('/api/auth', authRoutes);

export const startServer = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI as string);
    console.log('Connected to MongoDB');

    app.listen(port, () => {
      console.log(`Server is running at http://localhost:${port}`);
    });
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
};
