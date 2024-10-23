import { User, IUser, UserRole } from '../models/user.model';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { sendResetPasswordEmail } from '../utils/email.utils';

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

  static async login(email: string, password: string) {
    const user = await User.findOne({ email });
    if (!user) throw new Error('User not found');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error('Invalid credentials');

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET!, {
      expiresIn: '1h',
    });
    return { token, user };
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

  static async forgotPassword(email: string): Promise<boolean> {
    const user = await User.findOne({ email });
    if (!user) return false;

    // Generate a reset token that expires in 1 hour
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET!, { expiresIn: '1h' });

    await sendResetPasswordEmail(email, token);
    return true;
  }

  static async resetPassword(token: string, newPassword: string) {
    const user = await User.findOne({ otp: token });
    if (!user) throw new Error('Invalid or expired token');

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined; // Clear the token
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
