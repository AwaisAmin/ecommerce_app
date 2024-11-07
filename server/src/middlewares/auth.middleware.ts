// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload | string;
}

export const authenticateJWT = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET!, (err, user) => {
    if (err) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    req.user = user;
    next();
  });
};

export const isAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  if (req.user && typeof req.user === 'object' && 'role' in req.user) {
    if (req.user.role !== 'admin') {
      res.status(403).json({ message: 'Access denied: Admins only' });
      return;
    }
  } else {
    res.status(403).json({ message: 'Access denied: Invalid user' });
    return;
  }

  next();
};
