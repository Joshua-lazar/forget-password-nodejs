/**
 * User auth controllers
 * @author Yousuf Kalim
 */
const crypto = require('crypto');
const Users = require('../models/Users');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../utils/sendEmail');
const sendEmailFg = require('../utils/sendEmailFg');
const { decode } = require('jsonwebtoken');
const bcryptSalt = process.env.BCRYPT_SALT || 10;
const tokenSecret = process.env.JWT_SECRET;
const clientUrl = process.env.CLIENT_URL;

/**
 * Login
 * @param {object} req
 * @param {object} res
 */
exports.login = async (req, res) => {
  try {
    // Getting email and password
    const { email, password } = req.body;

    // Getting user from db
    const user = await Users.findOne({ email });

    if (!user) {
      // If user not found
      console.log(user);
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Comparing password
    const isMatched = bcrypt.compareSync(password, user.password);

    if (!isMatched) {
      // If password not matched
      return res.status(400).json({ success: false, message: 'Invalid Password' });
    }

    // Creating payload with user object
    const payload = { user };

    // Generating token
    jwt.sign(payload, tokenSecret, { expiresIn: 360000 }, (err, token) => {
      if (err) throw err;

      // done
      res.json({ success: true, user, token });
    });
  } catch (err) {
    // Error handling
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Change Password
 * @param {object} req
 * @param {object} res
 */
exports.changePassword = async (req, res) => {
  try {
    const { userId } = req.params;
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password and confirm password are not same',
      });
    }

    let user = await Users.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const isMatched = bcrypt.compareSync(oldPassword, user.password);

    if (!isMatched) {
      return res.status(400).json({ success: false, message: 'Invalid old Password' });
    }

    // Generate token
    user.password = bcrypt.hashSync(newPassword, parseInt(bcryptSalt));

    await user.save();

    res.json({ success: true, user });
  } catch (err) {
    // Error handling
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Forgot password
 * @param {object} req
 * @param {object} res
 */
exports.forgot = async (req, res) => {
  try {
    let { email } = req.params;
    let user = await Users.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Generating random password
    let randomPassword = Math.random().toString(36).slice(-8);

    // Sending email to user
    sendEmail(email, randomPassword)
      .then(async () => {
        // If email is sent then we have to update the password in db
        user.password = await bcrypt.hash(randomPassword, parseInt(bcryptSalt));
        await user.save();

        // Done
        res.json({ success: true, message: 'Email sent successfully' });
      })
      .catch((err) => {
        // Error handling
        console.log('Error ----> ', err);
        res.status(500).json({ success: false, message: 'Internal server error' });
      });
  } catch (err) {
    // Error handling
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Confirm auth
 * @param {object} req
 * @param {object} res
 */
exports.confirmAuth = async (req, res) => {
  // If user authenticated
  res.json({ success: true, user: req.user });
};

// Two way =================>

// 1

// // @desc      Forgot password
// // @route     POST api/auth/forgotpassword
// // @access    Public
// exports.ForgetPassword = async (req, res) => {
//   const user = await Users.findOne({ email: req.body.email });
//   if (!user) {
//     return res.status(404).json({ success: false, message: 'There is no user with that email' });
//   }
//   // Get reset token
//   const resetToken = user.getResetPasswordToken();
//   // const resetToken = user.getSignedJwtToken();

//   await user.save({ validateBeforeSave: false });

//   // Create reset url
//   const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/forgotpassword/${resetToken}`;
//   const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;
//   console.log(message);
//   try {
//     await sendEmailFg({
//       email: user.email,
//       subject: 'Password reset token',
//       message,
//     });
//     res.status(200).json({ success: true, data: 'Email sent' });
//   } catch (err) {
//     console.log(err);
//     user.resetPasswordToken = undefined;
//     user.resetPasswordExpire = undefined;

//     await user.save({ validateBeforeSave: false });

//     return res.status(500).json({ success: false, data: 'Email could not be sent' });
//   }
// };

// // @desc      Reset password
// // @route     PUT /api/auth/resetpassword/:resettoken
// // @access    Public
// exports.resetPassword = async (req, res) => {
//   // Get hashed token
//   const resetPasswordToken = crypto.createHash('sha256').update(req.params.resettoken).digest('hex');
//   const user = await Users.findOne({
//     resetPasswordToken,
//     resetPasswordExpire: { $gt: Date.now() },
//   });
//   console.log(user, 'user');

//   if (!user) {
//     return res.status(400).json({ success: false, data: 'Invalid token' });
//   }

//   // Set new password
//   const hashedPassword = bcrypt.hashSync(req.body.password, 10);
//   user.password = hashedPassword;
//   await user.save();

//   res.status(200).json({ success: true, message: 'Password updated successfully' });
// };

// ========================================
// 2
exports.ForgetPassword = async (req, res) => {
  const user = await Users.findOne({ email: req.body.email });
  if (!user) {
    console.log('There is no user with that email');
    return res.status(404).json({ success: false, message: 'There is no user with that email' });
  }
  // Get reset token
  const resetToken = user.getSignedJwtToken();
  // Create reset url
  const resetUrl = `${clientUrl}/forgotpassword/${resetToken}`;

  const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

  try {
    await sendEmailFg({
      email: user.email,
      subject: 'Password reset token',
      message,
    });
    res.status(200).json({ success: true, data: 'Please check your email inbox for a link to complete the reset.' });
  } catch (err) {
    return res.status(500).json({ success: false, data: 'Email could not be sent' });
  }
};

exports.verifyPasswordToken = async (req, res) => {
  try {
    const { resettoken } = req.params;
    const decoded = jwt.verify(resettoken, process.env.JWT_SECRET);
    const user = await Users.findOne({
      _id: decoded.id,
    });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({
      success: true,
      message: 'Token verified successfully',
      userId: user._id,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: 'Token Expired', error });
  }
};

// Reset the password
exports.resetPassword = async (req, res) => {
  try {
    const { resettoken } = req.params; // get the token  by   params
    const decoded = jwt.verify(resettoken, process.env.JWT_SECRET); // verify the Token

    const user = await Users.findOne({
      _id: decoded.id,
    });
    console.log(user);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);

    user.password = hashedPassword;
    await user.save();
    res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: 'internal server error', error });
  }
};
