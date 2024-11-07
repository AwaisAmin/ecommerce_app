import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { AppError } from '../utils/AppError';
import { setRefreshTokenCookie } from '../utils/token.utils';
import { JwtPayload } from 'jsonwebtoken';
import { AuthenticatedRequest } from '../middlewares/auth.middleware';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password, role } = req.body;
      const user = await AuthService.register(email, password, role);
      await AuthService.sendVerificationEmail(user);
      res.status(201).json({ message: 'User registered. Please verify your email.' });
    } catch (error) {
      console.error('Registration Error:', error);
      next(new AppError('Failed to register user', 400));
    }
  }

  static async verifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.params;
      const user = await AuthService.verifyEmail(token);
      res.status(200).json({ message: 'Email verified successfully', user });
    } catch (error) {
      next(new AppError('Invalid or expired email verification token', 400));
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body;
      const ip: string | undefined = req.ip;
      const userAgent: string = req.headers['user-agent'] || '';
      const result = await AuthService.login(email, password, ip!, userAgent);
      setRefreshTokenCookie(res, result.refreshToken);
      res.status(200).json({ token: result.token, user: result.user });
    } catch (error) {
      next(new AppError('Invalid login credentials', 400));
    }
  }

  static async logout(req: Request, res: Response, next: NextFunction) {
    try {
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      });

      res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
      next(new AppError('Failed to log out', 500));
    }
  }

  static async refreshToken(req: Request, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.cookies;
      const { token, newRefreshToken } = await AuthService.refreshToken(refreshToken);
      setRefreshTokenCookie(res, newRefreshToken);

      res.status(200).json({ token });
    } catch (error) {
      next(new AppError('Failed to refresh token', 400));
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;
      const { isEmailSent, resetToken } = await AuthService.forgotPassword(email);

      if (!isEmailSent) {
        return next(new AppError('User not found with that email', 404));
      }

      res.status(200).json({ message: 'Reset password email sent.', token: resetToken });
    } catch (error) {
      next(new AppError('Error processing password reset request', 500));
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.query;
      const { newPassword } = req.body;
      await AuthService.resetPassword(token as string, newPassword);
      res.status(200).json({ message: 'Password reset successfully.' });
    } catch (error) {
      next(new AppError('Failed to reset password', 400));
    }
  }

  // profile
  static async getProfile(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const user = req.user;
      res.status(200).json({ message: 'User profile', user });
    } catch (error) {
      next(new AppError('Failed to get profile', 500));
    }
  }

  static async googleLogin(req: Request, res: Response, next: NextFunction) {
    try {
      const { googleId } = req.body;
      const result = await AuthService.googleLogin(googleId);
      res.status(200).json(result);
    } catch (error) {
      next(new AppError('Google login failed', 400));
    }
  }
}
