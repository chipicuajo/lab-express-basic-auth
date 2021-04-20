const router = require("express").Router();
const bcrypt = require('bcryptjs');
const e = require("express");

const UserModel = require ('../models/User.model')

let userInfo = {};
router.get('/signin', (req,res)=>{
  res.render('auth/signin.hbs')
})

router.post('/signin', (req,res,next)=>{
  const{username,password} = req.body

//1. find user with email 
UserModel.findOne({username})
.then((result) => {
  if(!result){
    res.render('auth/signin', {msg: 'Username or password does not match any existing users'})
  }
  else{
    //2. compare the password with bcrypt
    bcrypt.compare(password, result.password)
    .then((pwdResult)=>{
        if(pwdResult){
          req.session.userInfo = result,
          req.app.locals.isUserLoggedIn = true 
          res.redirect('/profile')
        }else{
          res.render('auth/signin', {msg: 'Username or password does not match any existing users'})
        }
    })
  }
})
.catch((err) => {
  next(err)
});
})

/* GET home page */
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post('/signup', (req,res,next)=>{
  const {username, password} = req.body

  if(!username || !password){
    res.render('auth/signup.hbs', {msg: "please enter all fields"})
    return;
  }

  const passRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
  if(!passRe.test(password)){
    res.render('auth/signup.hbs', {msg: 'Password must be 8 characters, must have a number, and an uppercase letter'})
    //tell node to come out of the callback code
    return;
  }

  const salt = bcrypt.genSaltSync(12);
  const hash = bcrypt.hashSync(password, salt);

  UserModel.create({username, password: hash})
  .then((result) => {
    res.redirect('/')
  })
  .catch((err) => {
    next(err) // looks error handling middleware 
  });
})

const authorize = (req, res, next) =>{
  if(req.session.userInfo){
    next()
  }
  else{
    res.redirect('/')
  }
}

router.get('/profile',(req,res, next)=>{
  const {username} = req.session.userInfo
  res.render('profile.hbs', {username})
})

router.get('/logout', (req,res,next)=>{
  req.app.locals.isUserLoggedIn = false  
  req.session.destroy()
  res.redirect('/')
})

router.get('/main', authorize, (req,res, next)=>{
  if(req.app.locals.isUserLoggedIn){
    res.render('main.hbs')
  }else{
    res.redirect('/')
  }
})

router.get('/private', authorize, (req,res, next)=>{
  res.render('private.hbs')
  
})

module.exports = router;
