import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { AppError } from '../utils/AppError'; // Assuming you have a custom AppError class

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
      const result = await AuthService.login(email, password);
      res.status(200).json(result);
    } catch (error) {
      next(new AppError('Invalid login credentials', 400));
    }
  }

  static async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body;
      const isEmailSent = await AuthService.forgotPassword(email);

      if (!isEmailSent) {
        return next(new AppError('User not found with that email', 404));
      }

      res.status(200).json({ message: 'Reset password email sent.' });
    } catch (error) {
      next(new AppError('Error processing password reset request', 500));
    }
  }

  static async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.params;
      const { newPassword } = req.body;
      await AuthService.resetPassword(token, newPassword);
      res.status(200).json({ message: 'Password reset successfully.' });
    } catch (error) {
      next(new AppError('Failed to reset password', 400));
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
