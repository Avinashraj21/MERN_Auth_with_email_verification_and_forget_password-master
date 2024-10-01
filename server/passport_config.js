const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const User = require('./models/user_model');

// Function to extract JWT from cookies
function extractJwtFromCookie(req) {
    const token = req.cookies.access_token;
    return token;
}

// Local strategy for username/password authentication
passport.use(
    new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
        User.findOne({ email }, (err, user) => {
            if (err) return done(err);
            if (!user) return done(null, false); // User not found
            return user.comparePassword(password, done); // Validate password
        });
    })
);

// JWT strategy for token-based authentication
passport.use(
    new JwtStrategy(
        {
            jwtFromRequest: extractJwtFromCookie,
            secretOrKey: process.env.SECRET, // Make sure this is set
        },
        (payload, done) => {
            User.findById(payload.sub, (err, user) => {
                if (err) return done(err, false);
                if (user) return done(null, user); // Attach user to req.user
                return done(null, false); // User not found
            });
        }
    )
);
