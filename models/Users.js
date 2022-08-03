/**
 * User schema
 * @author Yousuf Kalim
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const mongoose = require('mongoose');

// Schema
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please add a valid email'],
    },
    password: {
      type: String,
      required: true,
      minlength: 8,
    },

    resetPasswordToken: String,
    resetPasswordExpire: Date,
    confirmEmailToken: String,
    isEmailConfirmed: {
      type: Boolean,
      default: false,
    },
    number: {
      type: String,
      required: true,
    },
    gender: {
      type: String,
      enum: ['male', 'female', ''],
    },
    role: {
      type: String,
      enum: ['admin', 'user', ''],
      default: 'user',
    },

    address: String,
    city: String,
    country: String,
    photo: String,
  },
  {
    timestamps: true,
  },
);

// Sign JWT and return
userSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: 360000,
  });
};

// --------------------------------------------------------------------------//

// Generate and hash password token --->
// userSchema.methods.getResetPasswordToken = function () {
//   // Generate token
//   const resetToken = crypto.randomBytes(20).toString('hex');

//   // Hash token and set to resetPasswordToken field
//   this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

//   // Set expire
//   this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

//   return resetToken;
// };

// --------------------------------------------------------------------------//
// Generate email confirm token
// userSchema.methods.generateEmailConfirmToken = function (next) {
//   // email confirmation token
//   const confirmationToken = crypto.randomBytes(20).toString('hex');

//   this.confirmEmailToken = crypto.createHash('sha256').update(confirmationToken).digest('hex');

//   const confirmTokenExtend = crypto.randomBytes(100).toString('hex');
//   const confirmTokenCombined = `${confirmationToken}.${confirmTokenExtend}`;
//   return confirmTokenCombined;
// };
// Model
module.exports = mongoose.model('users', userSchema);
