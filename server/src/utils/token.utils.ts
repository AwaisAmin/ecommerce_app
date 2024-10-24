import jwt from 'jsonwebtoken';
import { Response } from 'express';

export const generateAccessToken = (
  userId: string,
  role: string,
  ip: string,
  userAgent: string,
) => {
  return jwt.sign({ id: userId, role, ip, userAgent }, process.env.JWT_SECRET!, {
    expiresIn: '1h',
  });
};

export const generateRefreshToken = (userId: string, ip: string, userAgent: string) => {
  return jwt.sign({ id: userId, type: 'refresh', ip, userAgent }, process.env.JWT_SECRET!, {
    expiresIn: '30d',
  });
};

export const setRefreshTokenCookie = (res: Response, refreshToken: string) => {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
};
