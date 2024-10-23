import { Schema, model, Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  role: string;
  isVerified: boolean;
  googleId?: string;
  otp?: string;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'customer' },
  isVerified: { type: Boolean, default: false },
  googleId: { type: String },
  otp: { type: String },
});

export const User = model<IUser>('User', userSchema);
