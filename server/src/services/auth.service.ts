import { User, IUser, UserRole } from '../models/user.model';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { sendResetPasswordEmail } from '../utils/email.utils';
import { generateAccessToken, generateRefreshToken } from '../utils/token.utils';

export class AuthService {
  static async register(email: string, password: string, role: UserRole = UserRole.Customer) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword, role });
    await newUser.save();
    return newUser;
  }

  static async verifyEmail(token: string) {
    const user = await User.findOne({ otp: token });
    if (!user) throw new Error('Invalid OTP');
    user.isVerified = true;
    user.otp = undefined;
    await user.save();
    return user;
  }

  static async login(email: string, password: string, ip: string, userAgent: string) {
    const user = (await User.findOne({ email })) as IUser | null;
    if (!user) throw new Error('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error('Invalid credentials');

    const token = generateAccessToken(user._id.toString(), user.role, ip, userAgent);
    const refreshToken = generateRefreshToken(user._id.toString(), ip, userAgent);

    return { token, refreshToken, user };
  }

  static async refreshToken(refreshToken: string) {
    if (!refreshToken) throw new Error('Refresh token required');

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_SECRET!) as any;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }

    const user = await User.findById(payload.id);
    if (!user) throw new Error('User not found');

    const token = generateAccessToken(
      user._id.toString(),
      user.role,
      payload.ip,
      payload.userAgent,
    );
    const newRefreshToken = generateRefreshToken(
      user._id.toString(),
      payload.ip,
      payload.userAgent,
    );

    return { token, newRefreshToken };
  }

  static async sendVerificationEmail(user: IUser) {
    const otp = crypto.randomBytes(20).toString('hex');
    user.otp = otp;
    await user.save();

    const transporter = nodemailer.createTransport({
      host: 'smtp.mailtrap.io', // Mailtrap SMTP server
      port: 2525,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Email Verification',
      text: `Click the link to verify your email: ${process.env.FRONTEND_URL}/verify-email/${otp}`,
    };

    await transporter.sendMail(mailOptions);
  }

  static async forgotPassword(
    email: string,
  ): Promise<{ isEmailSent: boolean; resetToken?: string }> {
    const user = await User.findOne({ email });
    if (!user) return { isEmailSent: false };

    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET!, { expiresIn: '1h' });
    await sendResetPasswordEmail(email, resetToken);

    return { isEmailSent: true, resetToken };
  }

  static async resetPassword(token: string, newPassword: string) {
    const user = await User.findOne({ otp: token });
    if (!user) throw new Error('Invalid or expired token');

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    await user.save();
  }

  // Google Authentication
  static async googleLogin(googleId: string) {
    let user = await User.findOne({ googleId });
    if (!user) {
      user = new User({ googleId, isVerified: true });
      await user.save();
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET!, {
      expiresIn: '1h',
    });
    return { token, user };
  }
}
