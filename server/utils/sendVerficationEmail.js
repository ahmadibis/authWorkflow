const sendEmail = require('./sendEmail');

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  //so youll use the origin and the route to verify the email with the verification token from the query params
  //this route has to be present on the frontend tho
  //so on the frontend we when makign a post call we will attach the token from query url and the email too

  const verifyEmail = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  //so when you click the link sent to your mail it triggers the verify email in the controller and the token
  //gets passed in the url , yh so the link would have to go to your frontend , so from the frontend
  //we will send it back to the verifyemail route that the verify email controller handles
  const message = `<p>Please confirm your email by clicking on the following link : 
  <a href="${verifyEmail}">Verify Email</a> </p>`;

  return sendEmail({
    to: email,
    subject: "Email Confirmation",
    html: `<h4> Hello, ${name}</h4>
    ${message}
    `,
  });
};

module.exports = sendVerificationEmail;
