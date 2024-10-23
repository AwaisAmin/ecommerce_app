import { Schema, model, Document } from 'mongoose';

export enum UserRole {
  Customer = 'customer',
  Admin = 'admin',
}

export interface IUser extends Document {
  email: string;
  password: string;
  role: UserRole;
  isVerified: boolean;
  googleId?: string;
  otp?: string;
}

const userSchema = new Schema<IUser>(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: Object.values(UserRole),
      default: UserRole.Customer,
    },
    isVerified: { type: Boolean, default: false },
    googleId: { type: String },
    otp: { type: String },
  },
  {
    toObject: {
      versionKey: false, // Do not include the __v field
    },
  },
);

export const User = model<IUser>('User', userSchema);
