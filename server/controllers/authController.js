const User = require('../models/User');
const Token = require('../models/Token');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const {
  attachCookiesToResponse,
  createTokenUser,
  sendVerificationEmail,
  sendResetPasswordEmail,
  createHash,
} = require('../utils');
const crypto = require('crypto');

//when we register we dont want to send back the token ,
//we create the user 
//verify email
//so we send back the email only when the user click the a link in the mail means they are verified 
//we can add the verification token using crypto library and that is the token user will use to verify from
//frontend when login in
//so when creating i.e registeration a user we pass it in 
//for every user we attach their token to the user from the crypto library 

//we get the email and when we click on verify , we pass the token in the url and 
//in the frontend we can access the token value,

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError("Email already exists");
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? "admin" : "user";
  //we can add the verification token using crypto library and that is the token user will use to verify from
  //frontend when login in
  const verificationToken = crypto.randomBytes(40).toString("hex");

  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken,
  });
  const origin = "http://localhost:3000";
  // const newOrigin = 'https://react-node-user-workflow-front-end.netlify.app';

  // const tempOrigin = req.get('origin');
  // const protocol = req.protocol;
  // const host = req.get('host');
  // const forwardedHost = req.get('x-forwarded-host');
  // const forwardedProtocol = req.get('x-forwarded-proto');

  //after we create the user we send the verification email that would have the email and token 
  //the token you have created is what you are passing to get it verified 
  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });
  // send verification token back only while testing in postman!!!
  res.status(StatusCodes.CREATED).json({
    msg: "Success! Please check your email to verify account",
  });
};

//in the verify email we need to setup the verification token validity check and
// email and see if it is valid then you can log them in 
//so get the verification token 
//check for the email in the db if the user verification token matches what we have in 
//our db with what is coming from the the frontend
// we can set the isVerified to true
//meanining they are verified 

//so wehn i clieck on the link i send the token trough the url 
//i check if it matches what is in my db if so then i save the user and flip isVerified to true and inform the user 
//then i can login 

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  (user.isVerified = true), (user.verified = Date.now());
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
};

//so if the user is trying to login without verifying their account
// then they would be told to verify their mail
//so we will create a properverification token to verify and also send those emails to verify the emails 

//so when i login 

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError("Please provide email and password");
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError("Invalid Credentials");
  }
  const isPasswordCorrect = await user.comparePassword(password);

  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError("Invalid Credentials");
  }
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError("Please verify your email");
  }
  const tokenUser = createTokenUser(user);

  // create refresh token
  let refreshToken = "";
  // check for existing token
  const existingToken = await Token.findOne({ user: user._id });

  //if we have a existing token then check if it is still valid 
  if (existingToken) {
    const { isValid } = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError("Invalid Credentials");
    }

    refreshToken = existingToken.refreshToken;
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });
    res.status(StatusCodes.OK).json({ user: tokenUser });
    return;
  }
//otherwise
  //create a token and attach it to a user and attach the refreshtoken always to the user then take both token
  //place it in the cookie
  refreshToken = crypto.randomBytes(40).toString("hex");
  const userAgent = req.headers["user-agent"];
  const ip = req.ip;
  const userToken = { refreshToken, ip, userAgent, user: user._id };

  //creating the token 
  await Token.create(userToken);
//attaching it to the cookies with the refreshtoken
  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUser });
};

//we remove the tokens
const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.BadRequestError('Please provide valid email');
  }

  const user = await User.findOne({ email });

  //if we have a user
  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex');
    // send email
    const origin = 'http://localhost:3000';
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin,
    });

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    //storig the hashed password token
    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' });
};

//user types in their email to reset password 
//do all the checks
//find the user
//check token , expiration date, password token 
//then reset the password to the user password and save
const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values');
  }
  const user = await User.findOne({ email });

  if (user) {
    const currentDate = new Date();

    //user password token and the one im getting from the body , if the token expiration date is bigger than the current date 
    //then reset the password and reset the token and expiration date
    //we can compare the hashed toke cos we have stored it in the db so we are checking if it is the same hashed one we get 
    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }

  res.send('reset password');
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
