var express = require('express');
var mongoose = require('mongoose');
var passport = require('passport');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var User = require('./models/user');
var config = require('./config/database');
var cors = require('cors');
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');

// Set up an express app.
var app = express();

// Set up mongodb server.
mongoose.connect(config.database, {
    useNewUrlParser: true,
    useCreateIndex: true
});
mongoose.Promise = global.Promise;

// Set up Middlewares. 
app.use(cors());
app.use(express.urlencoded({
    extended: false
}));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());
require('./config/passport')(passport);

// Home route for API.
app.get('/', function (req, res) {
    res.json({
        api: 'v1.0',
        Message: 'Welcome to node-login API.'
    });
});

// Set up signup route
app.post('/signup', (req, res) => {
    if (!req.body.username && !req.body.password) {
        res.json({
            success: false,
            message: 'Please enter username and password.'
        });
    } else {
        //Encrpt password.
        bcrypt.hash(req.body.password, 12, function (err, hash) {
            if (err) {
                res.json({
                    success: false,
                    message: 'Password is invalid.'
                });
            } else {
                var newUser = new User({
                    username: req.body.username,
                    password: hash
                });
                // Store new user to mongodb.
                newUser.save(function (err) {
                    if (err) {
                        return res.json({
                            success: false,
                            message: 'Username exists.'
                        });
                    }
                    res.json({
                        success: true,
                        message: 'Successful created new user.'
                    });
                });
            }
        });
    }
});

// Login route for API.
app.post('/login', (req, res) => {
    if (req.body.username && req.body.password) {
        // Find user in Database.
        User.findOne({
            username: req.body.username
        }, function (err, user) {
            if (err) {
                console.log(err);
            } else {
                // Compare password. 
                user.comparePassword(req.body.password, function (error, isMatch) {
                    if (isMatch && !error) {
                        var token = jwt.sign(user.toJSON(), config.secret);
                        res.json({
                            success: true,
                            token: 'JWT ' + token
                        });
                    } else {
                        // Send status of Authorization.
                        res.status(401).send({
                            success: false,
                            msg: 'Authentication failed. Wrong password.'
                        });
                    }
                });
            }
        })
    }
});

// Function for get Token from header.
getToken = function (headers) {
    if (headers && headers.authorization) {
        var parted = headers.authorization.split(' ');
        if (parted.length === 2) {
            return parted[1];
        } else {
            return null;
        }
    } else {
        return null;
    }
};

// Home route for API.
app.post('/home', passport.authenticate('jwt', {
    session: false
}), (req, res) => {
    var token = getToken(req.headers);
    if (token) {
        
        User.find({}).then(users => {
            res.json({
                you: req.body,
                others: users
            });
        })
    } else {
        return res.status(403).send({
            success: false,
            msg: 'Unauthorized.'
        });
    }
});

// App listen port
app.listen(3000, () => {
    console.log(`Server started on port`);
});