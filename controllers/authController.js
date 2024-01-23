const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');

const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');

const signToken = id =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  //! Remove password from output
  user.password = undefined;

  res.cookie('jwt', token, cookieOptions);

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password!', 401));
  }

  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Get token and check of it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    return next(
      new AppError('You are not logged in! Please login to get access.', 401),
    );
  }

  // 2) Verification token
  const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exits
  const currentUser = await User.findById(decode.id);
  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does not longer exist.',
        401,
      ),
    );
  }

  // 4) check if user change password after the token was issued
  if (currentUser.changedPasswordAfter(decode.iat)) {
    return new AppError(
      'User recently changed password! Please login again.',
      401,
    );
  }

  // Grand access to protected route
  req.user = currentUser;
  next();
});

exports.restrictTo =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action!', 403),
      );
    }

    next();
  };

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on posted email
  const { email } = req.body;

  if (!email) {
    return next(new AppError('Please provide email!', 400));
  }

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError('There is no user with that email address.', 404));
  }
  // 2) Generate random reset token

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it's to user email
  const resetURL = `${req.protocol}://${req.get(
    'host',
  )}/api/v1/users/forgotPassword/${resetToken}`;
  const message = `Forgot password? Submit a PATCH request with your new password and passwordConfirm to : ${resetURL}\nIf you didn't forget your password, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid 10 min)',
      message,
    });
    res.status(200).json({
      status: 'success',
      message: 'Token send to email.',
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordTokenExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError(
        'There was an error sending an email. Try again later.',
        500,
      ),
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordTokenExpires: { $gt: Date.now() },
  });
  // 2) If token has not expired and user set new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired.', 400));
  }

  const { password, passwordConfirm } = req.body;

  if (!password && !passwordConfirm) {
    return next(
      new AppError('Please provide password & passwordConfirm!', 400),
    );
  }
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordTokenExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for the user
  // 4) Log in the user, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const { currentPassword, password, passwordConfirm } = req.body;
  // !need data type validation
  const user = await User.findById(req.user._id).select('+password');
  // 2) Check if posted password is correct
  if (!(await user.correctPassword(currentPassword, user.password))) {
    return next(new AppError('Current password not the same!', 400));
  }
  // 3) If so, update password
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  await user.save();
  // 4) Log user in, send jwt
  createSendToken(user, 200, res);
});
