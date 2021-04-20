const router = require("express").Router();
const bcrypt = require('bcryptjs')

const UserModel = require ('../models/User.model')
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


module.exports = router;
