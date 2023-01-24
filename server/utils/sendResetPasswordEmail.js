const sendEmail = require('./sendEmail');

const sendResetPassswordEmail = async ({ name, email, token, origin }) => {
  //so on the frontend we when makign a post call we will attach the token from query url and the email too
  //also we wsit for the reset password that we pass into the field for reset password in the reset pasword controller 
  const resetURL = `${origin}/user/reset-password?token=${token}&email=${email}`;
  const message = `<p>Please reset password by clicking on the following link : 
  <a href="${resetURL}">Reset Password</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4>Hello, ${name}</h4>
   ${message}
   `,
  });
};

module.exports = sendResetPassswordEmail;
