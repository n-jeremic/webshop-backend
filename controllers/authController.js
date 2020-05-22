const jwt = require('jsonwebtoken');

const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const User = require('../models/userModel');

const createToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  const token = createToken(newUser.id);

  res.status(200).json({
    status: 'success',
    token,
    expiresIn: 10800,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  if (!req.body.email || !req.body.password) {
    return next(new AppError('Invalid data submitted.', 400));
  }

  const user = await User.findOne({ email: req.body.email }).select('+password');
  if (!user || !(await user.correctPassword(req.body.password, user.password))) {
    return next(new AppError('Invalid email or password', 401));
  }

  const token = createToken(user.id);
  user.password = undefined;
  user.__v = undefined;

  res.status(200).json({
    status: 'success',
    token,
    expiresIn: 10800,
    data: {
      user,
    },
  });
});
