import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';

const router = Router();

router.post('/register', AuthController.register);
router.get('/verify-email/:token', AuthController.verifyEmail);
router.post('/login', AuthController.login);
router.post('/forgot-password', AuthController.forgotPassword);
router.post('/reset-password/:token', AuthController.resetPassword);
router.post('/google-login', AuthController.googleLogin);
router.post('/refresh-token', AuthController.refreshToken);
router.post('/logout', AuthController.logout);

export default router;
