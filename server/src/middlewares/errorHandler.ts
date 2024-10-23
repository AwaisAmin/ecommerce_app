import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/AppError';

export const errorHandler = (
  err: AppError | Error,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  console.error('Error:', err);

  if (err instanceof AppError) {
    return res.status(400).json({
      status: err.status,
      message: err.message,
    });
  }

  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!',
  });
};
