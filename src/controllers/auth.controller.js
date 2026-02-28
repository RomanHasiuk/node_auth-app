/* eslint-disable max-len */

import bcrypt from 'bcrypt';
import { userService } from '../services/user.service.js';
import { emailService } from '../services/email.service.js';
import { jwtService } from '../services/jwt.service.js';
import { tokenService } from '../services/token.service.js';
import { ApiError } from '../exceptions/api.error.js';

function validateEmail(value) {
  if (!value) {
    return 'Email is required';
  }

  const emailPattern = /^[\w.+-]+@([\w-]+\.){1,3}[\w-]{2,}$/;

  if (!emailPattern.test(value)) {
    return 'Email is not valid';
  }
}

function validatePassword(value) {
  if (!value) {
    return 'Password is required';
  }

  if (value.length < 6) {
    return 'Password must be at least 6 characters long';
  }

  if (!/[A-Z]/.test(value)) {
    return 'Password must contain at least one uppercase letter';
  }

  if (!/\d/.test(value)) {
    return 'Password must contain at least one number';
  }

  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(value)) {
    return 'Password must contain at least one special character (e.g., !@#$%^&*)';
  }
}

async function register(req, res) {
  const { email, password } = req.body;

  const validationErrors = {
    email: validateEmail(email),
    password: validatePassword(password),
  };

  if (validationErrors.email || validationErrors.password) {
    throw ApiError.BadRequest('Validation error', validationErrors);
  }

  if (!email || !password) {
    throw ApiError.BadRequest('Email and password are required');
  }

  const existingUser = await userService.getByEmail(email);

  if (existingUser) {
    throw ApiError.BadRequest('User already exists');
  }

  const user = await userService.create(email, password);

  await emailService.sendActivationLink(user.email, user.activationToken);

  res.status(201).json({
    message:
      'User registered successfully. Please check your email to activate your account.',
    user: {
      id: user.id,
      email: user.email,
    },
  });
}

async function activate(req, res) {
  const { activationToken } = req.params;
  const user = await userService.getByActivationToken(activationToken);

  if (!user) {
    throw ApiError.BadRequest('Invalid or expired activation link');
  }

  await userService.activate(user.id);

  res.status(200).json({ message: 'Account successfully activated' });
}

async function login(req, res) {
  const { email, password } = req.body;
  const user = await userService.getByEmail(email);

  if (!user) {
    throw ApiError.BadRequest('User with this email does not exist');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw ApiError.BadRequest('Password is wrong');
  }

  const userData = userService.normalize(user);
  const accessToken = jwtService.generateAccessToken(userData);
  const refreshToken = jwtService.generateRefreshToken(userData);

  await tokenService.save(user.id, refreshToken);

  res.cookie('refreshToken', refreshToken, {
    maxAge: 30 * 24 * 3600 * 1000,
    httpOnly: true,
  });

  res.send({
    user: userData,
    accessToken,
  });
}

async function refresh(req, res) {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    throw ApiError.Unauthorized();
  }

  const userData = jwtService.validateRefreshToken(refreshToken);

  if (!userData) {
    throw ApiError.Unauthorized();
  }

  const tokenFromDb = await tokenService.getByToken(refreshToken);

  if (!tokenFromDb) {
    throw ApiError.Unauthorized();
  }

  const user = await userService.getByEmail(userData.email);

  if (!user) {
    throw ApiError.Unauthorized();
  }

  const normalizedUser = userService.normalize(user);
  const newAccessToken = jwtService.generateAccessToken(normalizedUser);
  const newRefreshToken = jwtService.generateRefreshToken(normalizedUser);

  await tokenService.save(user.id, newRefreshToken);

  res.cookie('refreshToken', newRefreshToken, {
    maxAge: 30 * 24 * 3600 * 1000,
    httpOnly: true,
  });

  res.send({
    user: normalizedUser,
    accessToken: newAccessToken,
  });
}

async function logout(req, res) {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(204).send();
  }

  await tokenService.getByToken(refreshToken);

  res.clearCookie('refreshToken');

  res.status(200).json({
    message: 'Successfully fogged out',
  });
}

export const authController = {
  register,
  activate,
  login,
  refresh,
  logout,
};
