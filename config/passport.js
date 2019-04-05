var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;

var User = require('../models/user');
var config = require('../config/database');

module.exports = (passport) => {
    var opts = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
        secretOrKey: config.secret
    }
    passport.use(new JwtStrategy(opts, function (jwt_payload, done) {
        User.findOne({
            id: jwt_payload.sub
        }, function (err, user) {
            if (err) {
                return done(err, false);
            }
            if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        });
    }))
};