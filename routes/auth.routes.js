const {Router} = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {body, validationResult} = require('express-validator');
const config = require('config');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
  '/register',
  body('email', 'Wrong email').isEmail(),
  body('password', 'Minimal password length is 6 symbols')
    .isLength({min: 6}),
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect registration data'
        })
      }

      const {email, password} = req.body;

      const candidate = await User.findOne({email});

      if (candidate) {
        return res.status(400).json({message: `User with email ${email} already exists`});
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      await new User({email, password: hashedPassword}).save();

      res.status(201).json({message: 'User created'});

    } catch (e) {
      res.status(500).json({message: 'Something went wrong...'})
    }
  });

// /api/auth/login
router.post(
  '/login',
  body('email', 'Wrong email').normalizeEmail().isEmail(),
  body('password', 'Input password').exists(),
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect login data'
        })
      }

      const {email, password} = req.body;

      const user = await User.findOne({email});

      if (!user) {
        return res.status(400).json({message: `User doesn't exist`});
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({message: 'Wrong password'});
      }

      const token = jwt.sign(
        {userID: user.id},
        config.get('jwtSecret'),
        {expiresIn: '1h'}
      );

      res.status(200).json({token, userId: user.id});
    } catch (e) {
      res.status(500).json({message: 'Something went wrong...'})
    }
  });

module.exports = router;
