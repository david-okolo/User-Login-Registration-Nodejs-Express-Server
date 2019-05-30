const express = require('express');
const User = require('../models/user'); //contains all functions used inside the routes below.
const config = require('../config/database'); 
const passport = require('passport');
const jwt = require('jsonwebtoken');

const router = express.Router();

router.post('/register', (req, res, next) => {

    //registration route

    let newUser = new User({
        username: req.body.username,
        password: req.body.password,
        email: req.body.email,
        authLevel: req.body.authLevel
    });

    User.getUserByName(newUser.username, (err, user)=>{
        if(err) {
            res.json({
                success: false,
                msg: "Failed to connect"
            });
        }

        if(user){
            res.json({
                success: false,
                msg: "User already exists!"
            });
        }else {
            User.addUser(newUser, (err, user)=>{
                if(!err){
                    res.json({
                        success: true,
                        msg: "User created"
                    });
                } else {
                    res.json({
                        success: false,
                        msg: "Failed to create user"
                    })
                }
            });
        }
    });
});

router.post('/authenticate', (req, res, next) => {
    //the authentication route to create token and return minor user details. request is in JSON format with keys for username and password
    const username = req.body.username;
    const password = req.body.password;

    User.getUserByName(username, (err, user)=>{
        if (err) {
            res.json({
                success: false,
                msg: "Error: "+err
            });
        }

        if(!user){
            res.json({
                success:false,
                msg: 'User not found'
            })
        } else {
            User.comparePassword(password, user.password, (err, isMatch)=>{
                if(!err){
                    if(isMatch){
                        //creates the token
                        const token = jwt.sign(user.toObject(), config.secret, { 
                            expiresIn: "7d" //specify how long you want the token to remain valid default set here is 1 week
                        });
    
                        res.json({
                            success: true,
                            token: token,
                            username: user.username,
                            email: user.email,
                            authLevel: user.authLevel
                        });
                    }else{
                        res.json({
                            success: false,
                            msg: "Wrong Password"
                        });
                    }
                }else{
                    res.json({
                        success: false,
                        msg: "An error occurred"
                    });
                }
                
            });
        }
    });
});

router.get('/profile', passport.authenticate('jwt', {session: false}), (req, res, next)=>{
    User.getUserById(req.user._id, (err, user)=>{
        if (!err) {
            res.json(user); //returns the whole user object including password hash.
        }
    })
});

module.exports = router;